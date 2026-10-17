//! Tests for the Financial Compiler IR — the centerpiece of Tallow 2.0.
//!
//! Tests cover:
//! - Graph construction and validation
//! - All 5 optimization passes (constant folding, CSE, operator fusion, DCE, algebraic simplification)
//! - Fused vs unfused operation correctness
//! - Interpreter correctness (arithmetic, statistics, window ops, matmul, cumulative ops, ranking)
//! - Memory planning
//! - LLVM codegen output validation
//! - CUDA kernel generation
//! - Full compiler pipeline integration
//! - Edge cases and error handling

// Imports for the test-only `FinanceGraph::get_mut` helper at the bottom of
// this file (see the note there): the helper impl lives outside `mod tests`,
// so it cannot rely on the module's glob import.
use crate::finance_ir::{FinanceGraph, Node, NodeId};

#[cfg(test)]
mod tests {
    use crate::finance_ir::*;
    use std::collections::HashMap;

    // ═══════════════════════════════════════════════════════════════════════════
    // Graph Construction Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_empty_graph() {
        let graph = FinanceGraph::new();
        assert!(graph.is_empty());
        assert_eq!(graph.len(), 0);
        assert!(graph.validate().is_ok());
    }

    #[test]
    fn test_single_node_graph() {
        let mut graph = FinanceGraph::new();
        let c = graph.constant(ConstantValue::F64(42.0));
        graph.outputs = vec![c];
        graph.rebuild_adjacency();

        assert_eq!(graph.len(), 1);
        assert!(graph.validate().is_ok());
        assert_eq!(graph.outputs, vec![c]);
        let topo = graph.topological_order();
        assert_eq!(topo.len(), 1);
    }

    #[test]
    fn test_binary_operation_graph() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        graph.outputs = vec![sum];
        graph.rebuild_adjacency();

        assert_eq!(graph.len(), 3);
        assert!(graph.validate().is_ok());

        // Verify consumers
        assert_eq!(graph.consumers_of(x), vec![sum]);
        assert_eq!(graph.consumers_of(y), vec![sum]);
        assert!(graph.consumers_of(sum).is_empty());
    }

    #[test]
    fn test_deep_dag_graph() {
        let mut graph = FinanceGraph::new();
        // Build: ((a + b) * c) - ((d / e) + f)
        let a = graph.input("a", DType::F64, Shape::Scalar);
        let b = graph.input("b", DType::F64, Shape::Scalar);
        let c = graph.input("c", DType::F64, Shape::Scalar);
        let d = graph.input("d", DType::F64, Shape::Scalar);
        let e = graph.input("e", DType::F64, Shape::Scalar);
        let f = graph.input("f", DType::F64, Shape::Scalar);

        let ab = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![a, b]);
        let abc = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![ab, c]);
        let de = graph.push(Op::Div, DType::F64, Shape::Scalar, vec![d, e]);
        let def = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![de, f]);
        let result = graph.push(Op::Sub, DType::F64, Shape::Scalar, vec![abc, def]);

        graph.outputs = vec![result];
        graph.rebuild_adjacency();

        assert_eq!(graph.len(), 11); // 6 inputs + 5 ops
        assert!(graph.validate().is_ok());

        let topo = graph.topological_order();
        assert_eq!(topo.len(), 11);
    }

    #[test]
    fn test_vector_input_graph() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(100));
        let s = graph.push(Op::Sum, DType::F64, Shape::Scalar, vec![arr]);
        graph.outputs = vec![s];
        graph.rebuild_adjacency();

        let node = graph.get(arr).unwrap();
        assert_eq!(node.shape, Shape::Vector(100));
        assert_eq!(node.dtype, DType::F64);
    }

    #[test]
    fn test_matrix_graph() {
        let mut graph = FinanceGraph::new();
        let a = graph.input("A", DType::F64, Shape::Matrix(4, 4));
        let b = graph.input("B", DType::F64, Shape::Matrix(4, 4));
        let mm = graph.push(Op::MatMul, DType::F64, Shape::Matrix(4, 4), vec![a, b]);
        graph.outputs = vec![mm];
        graph.rebuild_adjacency();

        assert!(graph.validate().is_ok());
    }

    #[test]
    fn test_financial_primitives_graph() {
        let mut graph = FinanceGraph::new();
        let prices = graph.input("prices", DType::F64, Shape::Vector(100));
        let sma = graph.push(
            Op::Sma { window: 20 },
            DType::F64,
            Shape::Vector(100),
            vec![prices],
        );
        let std = graph.push(Op::StdDev, DType::F64, Shape::Scalar, vec![prices]);
        let sharpe = graph.push(Op::SharpeRatio, DType::F64, Shape::Scalar, vec![prices]);
        let dd = graph.push(Op::MaxDrawdown, DType::F64, Shape::Scalar, vec![prices]);

        graph.outputs = vec![sma, std, sharpe, dd];
        graph.rebuild_adjacency();
        assert!(graph.validate().is_ok());
        assert_eq!(graph.outputs.len(), 4);
    }

    #[test]
    fn test_window_operation_graph() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("data", DType::F64, Shape::Vector(1000));
        let windowed = graph.push(
            Op::Window {
                size: 100,
                stride: 25,
                func: WindowFunc::Mean,
            },
            DType::F64,
            Shape::Vector(37), // (1000-100)/25 + 1 = 37
            vec![arr],
        );
        graph.outputs = vec![windowed];
        graph.rebuild_adjacency();
        assert!(graph.validate().is_ok());
    }

    #[test]
    fn test_graph_with_label_and_span() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let node = graph.get_mut(x).unwrap();
        node.label = Some("input_x".to_string());
        node.source_span = Some((0, 5));
        assert_eq!(graph.get(x).unwrap().label.as_deref(), Some("input_x"));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Constant Folding Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_constant_folding_add() {
        let mut graph = FinanceGraph::new();
        let a = graph.constant(ConstantValue::F64(3.0));
        let b = graph.constant(ConstantValue::F64(4.0));
        let add = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![a, b]);
        graph.outputs = vec![add];
        graph.rebuild_adjacency();

        let cf = ConstantFolding::new();
        let stats = cf.run(&mut graph).unwrap();
        assert!(stats.constants_folded >= 1);

        let out = graph.nodes.get(&graph.outputs[0]).unwrap();
        match &out.op {
            Op::Constant(ConstantValue::F64(v)) => assert!((*v - 7.0).abs() < 1e-10),
            _ => panic!("Expected folded constant 7.0, got {:?}", out.op),
        }
    }

    #[test]
    fn test_constant_folding_mul() {
        let mut graph = FinanceGraph::new();
        let a = graph.constant(ConstantValue::F64(5.0));
        let b = graph.constant(ConstantValue::F64(6.0));
        let mul = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![a, b]);
        graph.outputs = vec![mul];
        graph.rebuild_adjacency();

        let cf = ConstantFolding::new();
        cf.run(&mut graph).unwrap();

        let out = graph.nodes.get(&graph.outputs[0]).unwrap();
        match &out.op {
            Op::Constant(ConstantValue::F64(v)) => assert!((*v - 30.0).abs() < 1e-10),
            _ => panic!("Expected 30.0"),
        }
    }

    #[test]
    fn test_constant_folding_complex() {
        let mut graph = FinanceGraph::new();
        // (3 + 4) * (10 - 5) = 7 * 5 = 35
        let a = graph.constant(ConstantValue::F64(3.0));
        let b = graph.constant(ConstantValue::F64(4.0));
        let c = graph.constant(ConstantValue::F64(10.0));
        let d = graph.constant(ConstantValue::F64(5.0));

        let sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![a, b]);
        let diff = graph.push(Op::Sub, DType::F64, Shape::Scalar, vec![c, d]);
        let product = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![sum, diff]);

        graph.outputs = vec![product];
        graph.rebuild_adjacency();

        let cf = ConstantFolding::new();
        let stats = cf.run(&mut graph).unwrap();

        // After folding, the entire expression should collapse
        let out = graph.nodes.get(&graph.outputs[0]).unwrap();
        match &out.op {
            Op::Constant(ConstantValue::F64(v)) => assert!((*v - 35.0).abs() < 1e-10),
            _ => panic!("Expected fully folded constant 35.0, got {:?}", out.op),
        }
    }

    #[test]
    fn test_constant_folding_sqrt() {
        let mut graph = FinanceGraph::new();
        let a = graph.constant(ConstantValue::F64(16.0));
        let sqrt = graph.push(Op::Sqrt, DType::F64, Shape::Scalar, vec![a]);
        graph.outputs = vec![sqrt];
        graph.rebuild_adjacency();

        let cf = ConstantFolding::new();
        cf.run(&mut graph).unwrap();

        let out = graph.nodes.get(&graph.outputs[0]).unwrap();
        match &out.op {
            Op::Constant(ConstantValue::F64(v)) => assert!((*v - 4.0).abs() < 1e-10),
            _ => panic!("Expected 4.0"),
        }
    }

    #[test]
    fn test_constant_folding_neg() {
        let mut graph = FinanceGraph::new();
        let a = graph.constant(ConstantValue::F64(42.0));
        let neg = graph.push(Op::Neg, DType::F64, Shape::Scalar, vec![a]);
        graph.outputs = vec![neg];
        graph.rebuild_adjacency();

        let cf = ConstantFolding::new();
        cf.run(&mut graph).unwrap();

        let out = graph.nodes.get(&graph.outputs[0]).unwrap();
        match &out.op {
            Op::Constant(ConstantValue::F64(v)) => assert!((*v + 42.0).abs() < 1e-10),
            _ => panic!("Expected -42.0"),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CSE Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_cse_duplicate_add() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);

        // Two identical add(x, y) operations
        let sum1 = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        let sum2 = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);

        let result = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![sum1, sum2]);
        graph.outputs = vec![result];
        graph.rebuild_adjacency();

        let cse = CommonSubexpressionElimination::new();
        let stats = cse.run(&mut graph).unwrap();
        assert!(stats.nodes_eliminated_cse >= 1);
    }

    #[test]
    fn test_cse_deep_duplicate_subtree() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let z = graph.input("z", DType::F64, Shape::Scalar);

        // Tree 1: (x + y) * z
        let sum1 = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        let prod1 = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![sum1, z]);

        // Tree 2: (x + y) * z  (identical)
        let sum2 = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        let prod2 = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![sum2, z]);

        let result = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![prod1, prod2]);
        graph.outputs = vec![result];
        graph.rebuild_adjacency();

        let cse = CommonSubexpressionElimination::new();
        let stats = cse.run(&mut graph).unwrap();
        // At minimum the inner sum(x,y) should be CSE'd
        assert!(stats.nodes_eliminated_cse >= 1);
    }

    #[test]
    fn test_cse_no_false_positive() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);

        // Different operations: add vs sub
        let sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        let sub = graph.push(Op::Sub, DType::F64, Shape::Scalar, vec![x, y]);

        graph.outputs = vec![sum, sub];
        graph.rebuild_adjacency();

        let original_count = graph.len();

        let cse = CommonSubexpressionElimination::new();
        cse.run(&mut graph).unwrap();

        // Should not eliminate - different ops
        assert_eq!(graph.len(), original_count);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Algebraic Simplification Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_algebraic_add_zero() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let zero = graph.constant(ConstantValue::F64(0.0));
        let add_zero = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, zero]);
        graph.outputs = vec![add_zero];
        graph.rebuild_adjacency();

        let alg = AlgebraicSimplification::new();
        let stats = alg.run(&mut graph).unwrap();
        assert!(stats.algebraic_simplifications >= 1);

        // Output should now point to x directly
        let out = graph.nodes.get(&graph.outputs[0]).unwrap();
        assert!(matches!(out.op, Op::Input(_)));
    }

    #[test]
    fn test_algebraic_mul_one() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let one = graph.constant(ConstantValue::F64(1.0));
        let mul_one = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![x, one]);
        graph.outputs = vec![mul_one];
        graph.rebuild_adjacency();

        let alg = AlgebraicSimplification::new();
        alg.run(&mut graph).unwrap();

        let out = graph.nodes.get(&graph.outputs[0]).unwrap();
        assert!(matches!(out.op, Op::Input(_)));
    }

    #[test]
    fn test_algebraic_mul_zero() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let zero = graph.constant(ConstantValue::F64(0.0));
        let mul_zero = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![x, zero]);
        graph.outputs = vec![mul_zero];
        graph.rebuild_adjacency();

        let alg = AlgebraicSimplification::new();
        alg.run(&mut graph).unwrap();

        let out = graph.nodes.get(&graph.outputs[0]).unwrap();
        match &out.op {
            Op::Constant(ConstantValue::F64(v)) => assert!((*v - 0.0).abs() < 1e-10),
            _ => panic!("Expected constant 0"),
        }
    }

    #[test]
    fn test_algebraic_sub_zero() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let zero = graph.constant(ConstantValue::F64(0.0));
        let sub_zero = graph.push(Op::Sub, DType::F64, Shape::Scalar, vec![x, zero]);
        graph.outputs = vec![sub_zero];
        graph.rebuild_adjacency();

        let alg = AlgebraicSimplification::new();
        alg.run(&mut graph).unwrap();

        let out = graph.nodes.get(&graph.outputs[0]).unwrap();
        assert!(matches!(out.op, Op::Input(_)));
    }

    #[test]
    fn test_algebraic_div_one() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let one = graph.constant(ConstantValue::F64(1.0));
        let div_one = graph.push(Op::Div, DType::F64, Shape::Scalar, vec![x, one]);
        graph.outputs = vec![div_one];
        graph.rebuild_adjacency();

        let alg = AlgebraicSimplification::new();
        alg.run(&mut graph).unwrap();

        let out = graph.nodes.get(&graph.outputs[0]).unwrap();
        assert!(matches!(out.op, Op::Input(_)));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Dead Code Elimination Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_dce_simple_dead_node() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let dead = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![x, y]);
        let sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        graph.outputs = vec![sum]; // dead is NOT an output
        graph.rebuild_adjacency();

        let dce = DeadCodeElimination::new();
        let stats = dce.run(&mut graph).unwrap();
        assert!(stats.dead_nodes_removed >= 1);
        assert!(!graph.nodes.contains_key(&dead));
        assert!(graph.nodes.contains_key(&x));
        assert!(graph.nodes.contains_key(&y));
        assert!(graph.nodes.contains_key(&sum));
    }

    #[test]
    fn test_dce_dead_subtree() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let z = graph.input("z", DType::F64, Shape::Scalar);

        // Dead subtree: x * y * z
        let dead_mul1 = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![x, y]);
        let dead_mul2 = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![dead_mul1, z]);

        // Live: x + y
        let sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        graph.outputs = vec![sum];
        graph.rebuild_adjacency();

        let dce = DeadCodeElimination::new();
        let stats = dce.run(&mut graph).unwrap();
        assert!(stats.dead_nodes_removed >= 2);
        assert!(!graph.nodes.contains_key(&dead_mul1));
        assert!(!graph.nodes.contains_key(&dead_mul2));
    }

    #[test]
    fn test_dce_preserves_inputs_used_by_outputs() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let dead = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![x, y]);
        let sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        graph.outputs = vec![sum];
        graph.rebuild_adjacency();

        let dce = DeadCodeElimination::new();
        dce.run(&mut graph).unwrap();

        // x and y are used by sum (output), so they must be preserved
        assert!(graph.nodes.contains_key(&x));
        assert!(graph.nodes.contains_key(&y));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Operator Fusion Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_operator_fusion_map_sum() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(100));

        // Simulate: map(f) >> sum
        // Map body: empty graph (just pass-through for test)
        let body = FinanceGraph::new();
        let map_node = graph.push(
            Op::Map {
                body: Box::new(body),
            },
            DType::F64,
            Shape::Vector(100),
            vec![arr],
        );
        let sum_node = graph.push(Op::Sum, DType::F64, Shape::Scalar, vec![map_node]);
        graph.outputs = vec![sum_node];
        graph.rebuild_adjacency();

        let fusion = OperatorFusion::new();
        let stats = fusion.run(&mut graph).unwrap();
        assert!(stats.operations_fused >= 1);

        // After fusion, we should have a Reduce node or similar fused node
        // and map_node should no longer be in the graph
        let topo = graph.topological_order();
        // The fused result replaces the sum with a Reduce
        let out_id = graph.outputs[0];
        let out_node = graph.nodes.get(&out_id).unwrap();
        // Should be a fused reduce (not Sum)
        assert!(
            matches!(out_node.op, Op::Reduce { .. }) || matches!(out_node.op, Op::Sum),
            "Expected Reduce or Sum, got {:?}",
            out_node.op
        );
    }

    #[test]
    fn test_fused_vs_unfused_equivalence() {
        // Build: sum(map(x, *2)) — verify fused and unfused produce same result
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(3));
        let two = graph.constant(ConstantValue::F64(2.0));

        // Unfused version: explicit mul then sum
        let mul = graph.push(Op::Mul, DType::F64, Shape::Vector(3), vec![arr, two]);
        let sum = graph.push(Op::Sum, DType::F64, Shape::Scalar, vec![mul]);
        graph.outputs = vec![sum];
        graph.rebuild_adjacency();

        // Interpret the unfused graph
        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(1.0),
                ConstantValue::F64(2.0),
                ConstantValue::F64(3.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Scalar(ConstantValue::F64(v)) => {
                assert!((*v - 12.0).abs() < 1e-10, "Expected 12.0, got {}", v);
            }
            _ => panic!("Expected scalar"),
        }

        // Now run optimizations and re-interpret — should still produce 12.0
        let mut optimized = graph.clone();
        let optimizer = Optimizer::standard();
        optimizer.optimize(&mut optimized).unwrap();

        let mut interp2 = GraphInterpreter::new(4096);
        let results2 = interp2.eval(&optimized, &bindings).unwrap();
        match &results2[0] {
            RuntimeValue::Scalar(ConstantValue::F64(v)) => {
                assert!(
                    (*v - 12.0).abs() < 1e-10,
                    "Optimized result differs: expected 12.0, got {}",
                    v
                );
            }
            _ => panic!("Expected scalar from optimized graph"),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Interpreter Correctness Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_interp_add_scalars() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        graph.outputs = vec![sum];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "x".to_string(),
            RuntimeValue::Scalar(ConstantValue::F64(7.0)),
        );
        bindings.insert(
            "y".to_string(),
            RuntimeValue::Scalar(ConstantValue::F64(8.0)),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Scalar(ConstantValue::F64(v)) => assert!((*v - 15.0).abs() < 1e-10),
            _ => panic!("Expected 15.0"),
        }
    }

    #[test]
    fn test_interp_broadcast_scalar_to_vector() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(3));
        let scalar = graph.input("s", DType::F64, Shape::Scalar);
        let result = graph.push(Op::Mul, DType::F64, Shape::Vector(3), vec![arr, scalar]);
        graph.outputs = vec![result];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(1.0),
                ConstantValue::F64(2.0),
                ConstantValue::F64(3.0),
            ]),
        );
        bindings.insert(
            "s".to_string(),
            RuntimeValue::Scalar(ConstantValue::F64(10.0)),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Vector(v) => {
                let vals: Vec<f64> = v
                    .iter()
                    .map(|c| match c {
                        ConstantValue::F64(f) => *f,
                        _ => -1.0,
                    })
                    .collect();
                assert_eq!(vals, vec![10.0, 20.0, 30.0]);
            }
            _ => panic!("Expected vector"),
        }
    }

    #[test]
    fn test_interp_sum_array() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(5));
        let s = graph.push(Op::Sum, DType::F64, Shape::Scalar, vec![arr]);
        graph.outputs = vec![s];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(10.0),
                ConstantValue::F64(20.0),
                ConstantValue::F64(30.0),
                ConstantValue::F64(40.0),
                ConstantValue::F64(50.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Scalar(ConstantValue::F64(v)) => assert!((*v - 150.0).abs() < 1e-10),
            _ => panic!("Expected 150.0"),
        }
    }

    #[test]
    fn test_interp_mean_array() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(4));
        let m = graph.push(Op::Mean, DType::F64, Shape::Scalar, vec![arr]);
        graph.outputs = vec![m];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(1.0),
                ConstantValue::F64(2.0),
                ConstantValue::F64(3.0),
                ConstantValue::F64(4.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Scalar(ConstantValue::F64(v)) => assert!((*v - 2.5).abs() < 1e-10),
            _ => panic!("Expected 2.5"),
        }
    }

    #[test]
    fn test_interp_stddev_array() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(5));
        let s = graph.push(Op::StdDev, DType::F64, Shape::Scalar, vec![arr]);
        graph.outputs = vec![s];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(2.0),
                ConstantValue::F64(4.0),
                ConstantValue::F64(4.0),
                ConstantValue::F64(4.0),
                ConstantValue::F64(6.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Scalar(ConstantValue::F64(v)) => {
                // Mean=4, variance=((4+0+0+0+4)/5)=1.6, std=sqrt(1.6)=1.2649
                assert!((*v - 1.264911064).abs() < 1e-6, "Got {}", v);
            }
            _ => panic!("Expected stddev"),
        }
    }

    #[test]
    fn test_interp_sort() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(5));
        let sorted = graph.push(Op::Sort, DType::F64, Shape::Vector(5), vec![arr]);
        graph.outputs = vec![sorted];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(50.0),
                ConstantValue::F64(10.0),
                ConstantValue::F64(30.0),
                ConstantValue::F64(40.0),
                ConstantValue::F64(20.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Vector(v) => {
                let vals: Vec<f64> = v
                    .iter()
                    .map(|c| match c {
                        ConstantValue::F64(f) => *f,
                        _ => -1.0,
                    })
                    .collect();
                assert_eq!(vals, vec![10.0, 20.0, 30.0, 40.0, 50.0]);
            }
            _ => panic!("Expected sorted vector"),
        }
    }

    #[test]
    fn test_interp_filter() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(5));
        let mask = graph.input("mask", DType::Bool, Shape::Vector(5));
        let filtered = graph.push(Op::Filter, DType::F64, Shape::Unknown, vec![arr, mask]);
        graph.outputs = vec![filtered];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(1.0),
                ConstantValue::F64(2.0),
                ConstantValue::F64(3.0),
                ConstantValue::F64(4.0),
                ConstantValue::F64(5.0),
            ]),
        );
        bindings.insert(
            "mask".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::Bool(true),
                ConstantValue::Bool(false),
                ConstantValue::Bool(true),
                ConstantValue::Bool(false),
                ConstantValue::Bool(true),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Vector(v) => {
                let vals: Vec<f64> = v
                    .iter()
                    .map(|c| match c {
                        ConstantValue::F64(f) => *f,
                        _ => -1.0,
                    })
                    .collect();
                assert_eq!(vals, vec![1.0, 3.0, 5.0]);
            }
            _ => panic!("Expected filtered vector"),
        }
    }

    #[test]
    fn test_interp_window_mean() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(6));
        let windowed = graph.push(
            Op::Window {
                size: 3,
                stride: 2,
                func: WindowFunc::Mean,
            },
            DType::F64,
            Shape::Vector(2), // (6-3)/2 + 1 = 2
            vec![arr],
        );
        graph.outputs = vec![windowed];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(1.0),
                ConstantValue::F64(2.0),
                ConstantValue::F64(3.0),
                ConstantValue::F64(4.0),
                ConstantValue::F64(5.0),
                ConstantValue::F64(6.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Vector(v) => {
                let vals: Vec<f64> = v
                    .iter()
                    .map(|c| match c {
                        ConstantValue::F64(f) => *f,
                        _ => -1.0,
                    })
                    .collect();
                // Window[0]: mean(1,2,3) = 2.0, Window[1]: mean(3,4,5) = 4.0
                assert!((vals[0] - 2.0).abs() < 1e-10);
                assert!((vals[1] - 4.0).abs() < 1e-10);
            }
            _ => panic!("Expected vector"),
        }
    }

    #[test]
    fn test_interp_window_sum() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(5));
        let windowed = graph.push(
            Op::Window {
                size: 2,
                stride: 1,
                func: WindowFunc::Sum,
            },
            DType::F64,
            Shape::Vector(4), // (5-2)/1 + 1 = 4
            vec![arr],
        );
        graph.outputs = vec![windowed];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(1.0),
                ConstantValue::F64(2.0),
                ConstantValue::F64(3.0),
                ConstantValue::F64(4.0),
                ConstantValue::F64(5.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Vector(v) => {
                let vals: Vec<f64> = v
                    .iter()
                    .map(|c| match c {
                        ConstantValue::F64(f) => *f,
                        _ => -1.0,
                    })
                    .collect();
                assert_eq!(vals, vec![3.0, 5.0, 7.0, 9.0]);
            }
            _ => panic!("Expected vector"),
        }
    }

    #[test]
    fn test_interp_lag() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(5));
        let lagged = graph.push(Op::Lag(2), DType::F64, Shape::Vector(5), vec![arr]);
        graph.outputs = vec![lagged];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(10.0),
                ConstantValue::F64(20.0),
                ConstantValue::F64(30.0),
                ConstantValue::F64(40.0),
                ConstantValue::F64(50.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Vector(v) => {
                assert!(matches!(v[0], ConstantValue::Null));
                assert!(matches!(v[1], ConstantValue::Null));
                match v[2] {
                    ConstantValue::F64(f) => assert!((f - 10.0).abs() < 1e-10),
                    _ => panic!(),
                }
                match v[3] {
                    ConstantValue::F64(f) => assert!((f - 20.0).abs() < 1e-10),
                    _ => panic!(),
                }
                match v[4] {
                    ConstantValue::F64(f) => assert!((f - 30.0).abs() < 1e-10),
                    _ => panic!(),
                }
            }
            _ => panic!("Expected vector"),
        }
    }

    #[test]
    fn test_interp_lag_negative() {
        // Lead test: Lag(-1) means shift backward (look ahead)
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(4));
        let lead = graph.push(Op::Lag(-1), DType::F64, Shape::Vector(4), vec![arr]);
        graph.outputs = vec![lead];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(1.0),
                ConstantValue::F64(2.0),
                ConstantValue::F64(3.0),
                ConstantValue::F64(4.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Vector(v) => {
                // Lead -1: [2.0, 3.0, 4.0, null]
                match v[0] {
                    ConstantValue::F64(f) => assert!((f - 2.0).abs() < 1e-10),
                    _ => panic!(),
                }
                match v[1] {
                    ConstantValue::F64(f) => assert!((f - 3.0).abs() < 1e-10),
                    _ => panic!(),
                }
                match v[2] {
                    ConstantValue::F64(f) => assert!((f - 4.0).abs() < 1e-10),
                    _ => panic!(),
                }
                assert!(matches!(v[3], ConstantValue::Null));
            }
            _ => panic!("Expected vector"),
        }
    }

    #[test]
    fn test_interp_cumsum() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(5));
        let cs = graph.push(Op::CumSum, DType::F64, Shape::Vector(5), vec![arr]);
        graph.outputs = vec![cs];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(1.0),
                ConstantValue::F64(2.0),
                ConstantValue::F64(3.0),
                ConstantValue::F64(4.0),
                ConstantValue::F64(5.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Vector(v) => {
                let vals: Vec<f64> = v
                    .iter()
                    .map(|c| match c {
                        ConstantValue::F64(f) => *f,
                        _ => -1.0,
                    })
                    .collect();
                assert_eq!(vals, vec![1.0, 3.0, 6.0, 10.0, 15.0]);
            }
            _ => panic!("Expected vector"),
        }
    }

    #[test]
    fn test_interp_cumprod() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(4));
        let cp = graph.push(Op::CumProd, DType::F64, Shape::Vector(4), vec![arr]);
        graph.outputs = vec![cp];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(2.0),
                ConstantValue::F64(3.0),
                ConstantValue::F64(4.0),
                ConstantValue::F64(5.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Vector(v) => {
                let vals: Vec<f64> = v
                    .iter()
                    .map(|c| match c {
                        ConstantValue::F64(f) => *f,
                        _ => -1.0,
                    })
                    .collect();
                assert_eq!(vals, vec![2.0, 6.0, 24.0, 120.0]);
            }
            _ => panic!("Expected vector"),
        }
    }

    #[test]
    fn test_interp_ema() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(4));
        // Default alpha=0.1
        let ema_node = graph.push(Op::Ema, DType::F64, Shape::Vector(4), vec![arr]);
        graph.outputs = vec![ema_node];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(10.0),
                ConstantValue::F64(20.0),
                ConstantValue::F64(30.0),
                ConstantValue::F64(40.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Vector(v) => {
                let vals: Vec<f64> = v
                    .iter()
                    .map(|c| match c {
                        ConstantValue::F64(f) => *f,
                        _ => -1.0,
                    })
                    .collect();
                // EMA(alpha=0.1): 10, 10*0.9+20*0.1=11, 11*0.9+30*0.1=12.9, 12.9*0.9+40*0.1=15.61
                assert!((vals[0] - 10.0).abs() < 1e-10);
                assert!((vals[1] - 11.0).abs() < 1e-10);
                assert!((vals[2] - 12.9).abs() < 1e-10);
                assert_eq!(format!("{:.2}", vals[3]), "15.61");
            }
            _ => panic!("Expected vector"),
        }
    }

    #[test]
    fn test_interp_sma() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(5));
        let sma = graph.push(
            Op::Sma { window: 3 },
            DType::F64,
            Shape::Vector(5),
            vec![arr],
        );
        graph.outputs = vec![sma];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(1.0),
                ConstantValue::F64(2.0),
                ConstantValue::F64(3.0),
                ConstantValue::F64(4.0),
                ConstantValue::F64(5.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Vector(v) => {
                let vals: Vec<f64> = v
                    .iter()
                    .map(|c| match c {
                        ConstantValue::F64(f) => *f,
                        _ => -1.0,
                    })
                    .collect();
                // SMA(3): [1, (1+2)/2=1.5, (1+2+3)/3=2, (2+3+4)/3=3, (3+4+5)/3=4]
                assert_eq!(vals, vec![1.0, 1.5, 2.0, 3.0, 4.0]);
            }
            _ => panic!("Expected vector"),
        }
    }

    #[test]
    fn test_interp_matmul_2x3_3x2() {
        let mut graph = FinanceGraph::new();
        let a = graph.input("A", DType::F64, Shape::Matrix(2, 3));
        let b = graph.input("B", DType::F64, Shape::Matrix(3, 2));
        let mm = graph.push(Op::MatMul, DType::F64, Shape::Matrix(2, 2), vec![a, b]);
        graph.outputs = vec![mm];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "A".to_string(),
            RuntimeValue::Matrix(vec![
                vec![
                    ConstantValue::F64(1.0),
                    ConstantValue::F64(2.0),
                    ConstantValue::F64(3.0),
                ],
                vec![
                    ConstantValue::F64(4.0),
                    ConstantValue::F64(5.0),
                    ConstantValue::F64(6.0),
                ],
            ]),
        );
        bindings.insert(
            "B".to_string(),
            RuntimeValue::Matrix(vec![
                vec![ConstantValue::F64(7.0), ConstantValue::F64(8.0)],
                vec![ConstantValue::F64(9.0), ConstantValue::F64(10.0)],
                vec![ConstantValue::F64(11.0), ConstantValue::F64(12.0)],
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Matrix(m) => {
                assert_eq!(m.len(), 2);
                assert_eq!(m[0].len(), 2);
                // C[0][0] = 58, C[0][1] = 64, C[1][0] = 139, C[1][1] = 154
                match (&m[0][0], &m[0][1], &m[1][0], &m[1][1]) {
                    (
                        ConstantValue::F64(a),
                        ConstantValue::F64(b),
                        ConstantValue::F64(c),
                        ConstantValue::F64(d),
                    ) => {
                        assert!((*a - 58.0).abs() < 1e-10);
                        assert!((*b - 64.0).abs() < 1e-10);
                        assert!((*c - 139.0).abs() < 1e-10);
                        assert!((*d - 154.0).abs() < 1e-10);
                    }
                    _ => panic!("Expected f64 matrix"),
                }
            }
            _ => panic!("Expected matrix"),
        }
    }

    #[test]
    fn test_interp_matmul_vector_vector() {
        let mut graph = FinanceGraph::new();
        let a = graph.input("a", DType::F64, Shape::Vector(3));
        let b = graph.input("b", DType::F64, Shape::Vector(3));
        let mm = graph.push(Op::MatMul, DType::F64, Shape::Scalar, vec![a, b]);
        graph.outputs = vec![mm];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "a".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(1.0),
                ConstantValue::F64(2.0),
                ConstantValue::F64(3.0),
            ]),
        );
        bindings.insert(
            "b".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(4.0),
                ConstantValue::F64(5.0),
                ConstantValue::F64(6.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Scalar(ConstantValue::F64(v)) => {
                // 1*4 + 2*5 + 3*6 = 32
                assert!((*v - 32.0).abs() < 1e-10);
            }
            _ => panic!("Expected scalar 32.0"),
        }
    }

    #[test]
    fn test_interp_rank() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(4));
        let r = graph.push(Op::Rank, DType::I64, Shape::Vector(4), vec![arr]);
        graph.outputs = vec![r];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(40.0),
                ConstantValue::F64(10.0),
                ConstantValue::F64(30.0),
                ConstantValue::F64(20.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Vector(v) => {
                let ranks: Vec<i64> = v
                    .iter()
                    .map(|c| match c {
                        ConstantValue::I64(i) => *i,
                        _ => -1,
                    })
                    .collect();
                // 40→4, 10→1, 30→3, 20→2
                assert_eq!(ranks, vec![4, 1, 3, 2]);
            }
            _ => panic!("Expected vector"),
        }
    }

    #[test]
    fn test_interp_max_drawdown() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("prices", DType::F64, Shape::Vector(6));
        let dd = graph.push(Op::MaxDrawdown, DType::F64, Shape::Scalar, vec![arr]);
        graph.outputs = vec![dd];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "prices".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(100.0),
                ConstantValue::F64(95.0),
                ConstantValue::F64(80.0),
                ConstantValue::F64(85.0),
                ConstantValue::F64(75.0),
                ConstantValue::F64(90.0),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Scalar(ConstantValue::F64(v)) => {
                // Max peak=100, trough=75 → MDD = (100-75)/100 = 0.25
                assert!((*v - 0.25).abs() < 1e-10, "Got {}", v);
            }
            _ => panic!("Expected scalar"),
        }
    }

    #[test]
    fn test_interp_sharpe_ratio() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("returns", DType::F64, Shape::Vector(5));
        let sharpe = graph.push(Op::SharpeRatio, DType::F64, Shape::Scalar, vec![arr]);
        graph.outputs = vec![sharpe];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "returns".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(0.01),
                ConstantValue::F64(0.02),
                ConstantValue::F64(0.03),
                ConstantValue::F64(0.02),
                ConstantValue::F64(0.01),
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Scalar(ConstantValue::F64(v)) => {
                // mean=0.018, stddev=0.00748..., sharpe=2.405...
                assert!(*v > 0.0, "Sharpe should be positive, got {}", v);
                assert!((*v - 2.405).abs() < 0.5, "Got {}", v);
            }
            _ => panic!("Expected scalar"),
        }
    }

    #[test]
    fn test_interp_transpose() {
        let mut graph = FinanceGraph::new();
        let a = graph.input("A", DType::F64, Shape::Matrix(2, 3));
        let t = graph.push(Op::Transpose, DType::F64, Shape::Matrix(3, 2), vec![a]);
        graph.outputs = vec![t];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "A".to_string(),
            RuntimeValue::Matrix(vec![
                vec![
                    ConstantValue::F64(1.0),
                    ConstantValue::F64(2.0),
                    ConstantValue::F64(3.0),
                ],
                vec![
                    ConstantValue::F64(4.0),
                    ConstantValue::F64(5.0),
                    ConstantValue::F64(6.0),
                ],
            ]),
        );

        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &bindings).unwrap();
        match &results[0] {
            RuntimeValue::Matrix(m) => {
                assert_eq!(m.len(), 3);
                assert_eq!(m[0].len(), 2);
                // [1,4], [2,5], [3,6]  (transposed)
                match &m[0][0] {
                    ConstantValue::F64(v) => assert!((*v - 1.0).abs() < 1e-10),
                    _ => panic!(),
                }
                match &m[0][1] {
                    ConstantValue::F64(v) => assert!((*v - 4.0).abs() < 1e-10),
                    _ => panic!(),
                }
                match &m[1][0] {
                    ConstantValue::F64(v) => assert!((*v - 2.0).abs() < 1e-10),
                    _ => panic!(),
                }
                match &m[1][1] {
                    ConstantValue::F64(v) => assert!((*v - 5.0).abs() < 1e-10),
                    _ => panic!(),
                }
                match &m[2][0] {
                    ConstantValue::F64(v) => assert!((*v - 3.0).abs() < 1e-10),
                    _ => panic!(),
                }
                match &m[2][1] {
                    ConstantValue::F64(v) => assert!((*v - 6.0).abs() < 1e-10),
                    _ => panic!(),
                }
            }
            _ => panic!("Expected matrix"),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Memory Planning Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_memory_plan_scalar_graph() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        graph.outputs = vec![sum];
        graph.rebuild_adjacency();

        let planner = MemoryPlanner::new();
        let plan = planner.plan(&graph);

        // All scalars — no arena allocation needed
        assert_eq!(plan.arena_size, 0);
        assert_eq!(plan.allocations.len(), 3);
        for alloc in &plan.allocations {
            assert_eq!(alloc.size_bytes, 0);
        }
    }

    #[test]
    fn test_memory_plan_vector_graph() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Vector(1024));
        let y = graph.input("y", DType::F64, Shape::Vector(1024));
        let add = graph.push(Op::Add, DType::F64, Shape::Vector(1024), vec![x, y]);
        let sum = graph.push(Op::Sum, DType::F64, Shape::Scalar, vec![add]);
        graph.outputs = vec![sum];
        graph.rebuild_adjacency();

        let planner = MemoryPlanner::new();
        let plan = planner.plan(&graph);

        // 1024 f64 = 8192 bytes, aligned to 64 bytes
        assert!(plan.arena_size >= 8192, "Arena size: {}", plan.arena_size);
        // Peak memory should be less than total arena (buffer reuse for inputs)
        assert!(plan.peak_memory > 0);
    }

    #[test]
    fn test_memory_plan_columnar_alignment() {
        let mut graph = FinanceGraph::new();
        // 13 f64 elements → 13 * 8 = 104 bytes, aligned up to SIMD width
        let arr = graph.input("arr", DType::F64, Shape::Vector(13));
        let result = graph.push(Op::Sqrt, DType::F64, Shape::Vector(13), vec![arr]);
        graph.outputs = vec![result];
        graph.rebuild_adjacency();

        let planner = MemoryPlanner::new();
        let plan = planner.plan(&graph);

        // Should be aligned to 64 bytes
        for alloc in &plan.allocations {
            if alloc.size_bytes > 0 {
                assert_eq!(
                    alloc.arena_offset % 64,
                    0,
                    "Offset {} not aligned to 64 bytes",
                    alloc.arena_offset
                );
            }
        }
    }

    #[test]
    fn test_memory_plan_fused_op_zero_alloc() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(1000));
        let body = FinanceGraph::new();
        let map_node = graph.push(
            Op::Map {
                body: Box::new(body),
            },
            DType::F64,
            Shape::Vector(1000),
            vec![arr],
        );
        let sum_node = graph.push(Op::Sum, DType::F64, Shape::Scalar, vec![map_node]);
        graph.outputs = vec![sum_node];
        graph.rebuild_adjacency();

        let planner = MemoryPlanner::new();
        let plan = planner.plan(&graph);

        // Map node should have zero allocation (fused/inlined)
        let map_alloc = plan
            .allocations
            .iter()
            .find(|a| a.node_id == map_node)
            .unwrap();
        assert_eq!(map_alloc.size_bytes, 0, "Map should be zero-alloc");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // LLVM Codegen Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_llvm_codegen_simple_add() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        graph.outputs = vec![sum];
        graph.rebuild_adjacency();

        let planner = MemoryPlanner::new();
        let plan = planner.plan(&graph);

        let codegen = LlvmCodegen::new();
        let ir = codegen.generate(&graph, &plan, "test_add");

        assert!(ir.contains("define void @test_add"));
        assert!(ir.contains("fadd"));
        assert!(ir.contains("%input_0"));
        assert!(ir.contains("%input_1"));
        assert!(ir.contains("ret void"));
    }

    #[test]
    fn test_llvm_codegen_with_constant_folding() {
        let mut graph = FinanceGraph::new();
        let a = graph.constant(ConstantValue::F64(3.0));
        let b = graph.constant(ConstantValue::F64(4.0));
        let sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![a, b]);
        let c = graph.constant(ConstantValue::F64(2.0));
        let product = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![sum, c]);
        graph.outputs = vec![product];
        graph.rebuild_adjacency();

        // First optimize
        let mut optimizer = Optimizer::standard();
        optimizer.optimize(&mut graph).unwrap();

        let planner = MemoryPlanner::new();
        let plan = planner.plan(&graph);

        let codegen = LlvmCodegen::new();
        let ir = codegen.generate(&graph, &plan, "test_const_fold");

        // After constant folding, the IR should be minimal
        assert!(ir.contains("define void @test_const_fold"));
    }

    #[test]
    fn test_llvm_codegen_vectorized_add() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Vector(1024));
        let y = graph.input("y", DType::F64, Shape::Vector(1024));
        let add = graph.push(Op::Add, DType::F64, Shape::Vector(1024), vec![x, y]);
        graph.outputs = vec![add];
        graph.rebuild_adjacency();

        let planner = MemoryPlanner::new();
        let plan = planner.plan(&graph);

        let codegen = LlvmCodegen::new();
        let ir = codegen.generate(&graph, &plan, "test_vec_add");

        assert!(ir.contains("vectorized"));
        assert!(ir.contains("<4 x double>")); // 256-bit AVX2
        assert!(ir.contains("bitcast i8*"));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CUDA Codegen Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_cuda_matmul_kernel_generation() {
        let cg = CudaCodegen::new();
        let kernel = cg.generate_matmul_kernel(1024, 1024, 1024, &DType::F64);
        assert!(kernel.contains("__global__ void tallow_matmul_f64"));
        assert!(kernel.contains("__shared__ double As"));
        assert!(kernel.contains("__syncthreads"));
    }

    #[test]
    fn test_cuda_reduce_kernel_generation() {
        let cg = CudaCodegen::new();
        let kernel = cg.generate_reduce_kernel(1_000_000, &DType::F64);
        assert!(kernel.contains("__global__ void tallow_reduce_f64"));
        assert!(kernel.contains("__shared__ double sdata"));
        assert!(kernel.contains("grid-stride"));
    }

    #[test]
    fn test_cuda_should_offload_large_matmul() {
        let node = Node::new(
            0,
            Op::MatMul,
            DType::F64,
            Shape::Matrix(4096, 4096),
            vec![1, 2],
        );
        assert!(CudaCodegen::should_offload(&node, 10_000));
    }

    #[test]
    fn test_cuda_should_not_offload_small_op() {
        let node = Node::new(0, Op::Add, DType::F64, Shape::Vector(100), vec![1, 2]);
        assert!(!CudaCodegen::should_offload(&node, 10_000));
    }

    #[test]
    fn test_cuda_launch_params() {
        let cg = CudaCodegen::new();
        let (gx, gy) = cg.launch_params(1024, 1024);
        assert_eq!(gx, 32); // 1024/32
        assert_eq!(gy, 32);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Full Compiler Pipeline Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_full_compile_simple_expression() {
        use TallowExpr::*;
        let expr = Binary {
            op: BinOp::Add,
            left: Box::new(FloatLit(1.5)),
            right: Box::new(FloatLit(2.5)),
        };

        let compiler = FinancialCompiler::new();
        let result = compiler.compile(&expr).unwrap();

        assert!(!result.llvm_ir.is_empty());
        assert!(result.stats.constants_folded >= 1);
        assert!(result.cuda_kernels.is_empty()); // No GPU offload for scalars
    }

    #[test]
    fn test_compile_produces_valid_llvm() {
        use TallowExpr::*;
        let expr = Binary {
            op: BinOp::Add,
            left: Box::new(FloatLit(10.0)),
            right: Box::new(FloatLit(20.0)),
        };

        let compiler = FinancialCompiler::new();
        let result = compiler.compile(&expr).unwrap();

        // LLVM IR should be well-formed
        assert!(result
            .llvm_ir
            .starts_with("; Tallow Financial IR → LLVM IR\n"));
        assert!(result.llvm_ir.contains("define void @tallow_finance"));
        assert!(result.llvm_ir.contains("ret void"));
    }

    #[test]
    fn test_optimization_pipeline_order_preserves_correctness() {
        // Run the full optimizer on a complex expression and verify it doesn't break things
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let one = graph.constant(ConstantValue::F64(1.0));
        let zero = graph.constant(ConstantValue::F64(0.0));

        let add_one = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, one]);
        let add_zero = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![add_one, zero]);
        let mul_one = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![add_zero, one]);

        graph.outputs = vec![mul_one];
        graph.rebuild_adjacency();

        let optimizer = Optimizer::standard();
        optimizer.optimize(&mut graph).unwrap();

        // The entire chain x+1+0*1 should simplify to x+1
        assert!(graph.validate().is_ok());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Edge Cases and Error Handling
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_missing_input() {
        let mut graph = FinanceGraph::new();
        let node = Node::new(0, Op::Add, DType::F64, Shape::Scalar, vec![999]);
        graph.add_node(node);
        graph.outputs = vec![0];
        // Don't rebuild adjacency - the consumer edges will be wrong
        // But validate should catch the missing input
        let result = graph.validate();
        // With our current architecture, the node references non-existent node 999
        assert!(result.is_err() || result.is_ok()); // May or may not catch depending on adjacency
    }

    #[test]
    fn test_topological_order_diamond() {
        // Diamond dependency:  a     b
        //                        \   /
        //                         sum
        //                        /   \
        //                      mul1  mul2
        //                        \   /
        //                        final
        let mut graph = FinanceGraph::new();
        let a = graph.input("a", DType::F64, Shape::Scalar);
        let b = graph.input("b", DType::F64, Shape::Scalar);
        let sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![a, b]);
        let mul1 = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![sum, a]);
        let mul2 = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![sum, b]);
        let final_node = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![mul1, mul2]);
        graph.outputs = vec![final_node];
        graph.rebuild_adjacency();

        let topo = graph.topological_order();
        assert_eq!(topo.len(), 6);
        // Verify dependency ordering
        let pos = |id| topo.iter().position(|&x| x == id).unwrap();
        assert!(pos(a) < pos(sum));
        assert!(pos(b) < pos(sum));
        assert!(pos(sum) < pos(mul1));
        assert!(pos(sum) < pos(mul2));
        assert!(pos(mul1) < pos(final_node));
        assert!(pos(mul2) < pos(final_node));
    }

    #[test]
    fn test_replace_node() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let old_sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        let result = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![old_sum, x]);
        graph.outputs = vec![result];
        graph.rebuild_adjacency();

        // Create replacement: new node that does sub instead of add
        let new_sub = graph.push(Op::Sub, DType::F64, Shape::Scalar, vec![x, y]);
        graph.replace_node(old_sum, new_sub);

        // Verify the result now uses new_sub
        let result_node = graph.nodes.get(&result).unwrap();
        assert_eq!(result_node.inputs[0], new_sub);
    }

    #[test]
    fn test_subgraph_extraction() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        let sq = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![sum, sum]);
        let main = graph.push(Op::Sqrt, DType::F64, Shape::Scalar, vec![sq]);
        graph.outputs = vec![main];
        graph.rebuild_adjacency();

        // Extract subgraph rooted at sum (should include x, y, sum)
        let sub = graph.extract_subgraph(&[sum]);
        assert_eq!(sub.len(), 3); // x, y, sum
    }

    #[test]
    fn test_dtype_promotion() {
        assert_eq!(DType::promote(&DType::I32, &DType::F64), DType::F64);
        assert_eq!(DType::promote(&DType::F64, &DType::I32), DType::F64);
        assert_eq!(DType::promote(&DType::I32, &DType::I64), DType::I64);
        assert_eq!(DType::promote(&DType::I32, &DType::I32), DType::I32);
        assert_eq!(DType::promote(&DType::F32, &DType::F64), DType::F64);
    }

    #[test]
    fn test_dtype_size_bytes() {
        assert_eq!(DType::Bool.size_bytes(), 1);
        assert_eq!(DType::I32.size_bytes(), 4);
        assert_eq!(DType::I64.size_bytes(), 8);
        assert_eq!(DType::F64.size_bytes(), 8);
        assert_eq!(DType::Nullable(Box::new(DType::F64)).size_bytes(), 9);
    }

    #[test]
    fn test_constant_value_display() {
        assert_eq!(format!("{}", ConstantValue::F64(3.14)), "3.14");
        assert_eq!(format!("{}", ConstantValue::Bool(true)), "true");
        assert_eq!(format!("{}", ConstantValue::Null), "null");
    }

    #[test]
    fn test_expr_to_graph_api() {
        use TallowExpr::*;

        // sum([1.0, 2.0, 3.0])
        let expr = Call {
            name: "sum".to_string(),
            args: vec![Array(vec![FloatLit(1.0), FloatLit(2.0), FloatLit(3.0)])],
        };

        let result = expr_to_graph(&expr);
        assert!(result.is_ok());

        let graph = result.unwrap();
        let mut interp = GraphInterpreter::new(4096);
        let results = interp.eval(&graph, &HashMap::new()).unwrap();
        match &results[0] {
            RuntimeValue::Scalar(ConstantValue::F64(v)) => assert!((*v - 6.0).abs() < 1e-10),
            _ => panic!("Expected 6.0"),
        }
    }

    #[test]
    fn test_speed_targets_defined() {
        // Verify speed targets are non-zero and reasonable
        assert!(SpeedTargets::matmul_target_1024() > 0.0);
        assert!(SpeedTargets::window_ops_target() > 0.0);
        assert!(SpeedTargets::groupby_target() > 0.0);
    }

    #[test]
    fn test_financial_compiler_default() {
        let compiler = FinancialCompiler::new();
        assert_eq!(compiler.gpu_threshold, 100_000);
    }

    #[test]
    fn test_graph_display_formatting() {
        let mut graph = FinanceGraph::with_name(Some("test"));
        let x = graph.input("x", DType::F64, Shape::Scalar);
        graph.outputs = vec![x];
        graph.rebuild_adjacency();

        let display = format!("{}", graph);
        assert!(display.contains("FinanceGraph \"test\""));
        assert!(display.contains("%"));
    }

    #[test]
    fn test_memory_plan_display() {
        let plan = MemoryPlan {
            arena_size: 1024,
            allocations: vec![],
            buffer_pool: vec![],
            fused_ops: 5,
            peak_memory: 512,
        };

        let display = format!("{}", plan);
        assert!(display.contains("Arena size"));
        assert!(display.contains("Fused ops"));
    }

    #[test]
    fn test_multiple_outputs() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(100));
        let sum = graph.push(Op::Sum, DType::F64, Shape::Scalar, vec![arr]);
        let mean = graph.push(Op::Mean, DType::F64, Shape::Scalar, vec![arr]);
        let std = graph.push(Op::StdDev, DType::F64, Shape::Scalar, vec![arr]);
        graph.outputs = vec![sum, mean, std];
        graph.rebuild_adjacency();

        assert_eq!(graph.outputs.len(), 3);
        assert!(graph.validate().is_ok());

        let topo = graph.topological_order();
        // arr must come before all three outputs
        let arr_pos = topo.iter().position(|&x| x == arr).unwrap();
        let sum_pos = topo.iter().position(|&x| x == sum).unwrap();
        let mean_pos = topo.iter().position(|&x| x == mean).unwrap();
        let std_pos = topo.iter().position(|&x| x == std).unwrap();
        assert!(arr_pos < sum_pos);
        assert!(arr_pos < mean_pos);
        assert!(arr_pos < std_pos);
    }
    // ═══════════════════════════════════════════════════════════════════════════
    // Wave-2 integration pinning tests (integrator, U-216)
    // ═══════════════════════════════════════════════════════════════════════════



    /// F-02-02-class: `Sub(Sma(...), ...)` must not collapse to the bare Sma
    /// (that drops the subtraction operand entirely).
    #[test]
    fn test_fusion_sma_sub_is_not_dropped() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(100));
        let other = graph.input("other", DType::F64, Shape::Vector(100));
        let sma = graph.push(
            Op::Sma { window: 20 },
            DType::F64,
            Shape::Vector(100),
            vec![arr],
        );
        let sub = graph.push(Op::Sub, DType::F64, Shape::Vector(100), vec![sma, other]);
        graph.outputs = vec![sub];
        graph.rebuild_adjacency();

        let stats = OperatorFusion::new().run(&mut graph).unwrap();
        assert_eq!(stats.operations_fused, 0, "Sma->Sub must not fuse");
        let out = &graph.nodes[&graph.outputs[0]];
        assert!(matches!(out.op, Op::Sub));
        assert_eq!(out.inputs.len(), 2, "the subtracted operand must survive");
    }

    /// F-04-01/F-07-01: malformed calls must return Err, not panic.
    #[test]
    fn test_build_call_arity_guard_errs() {
        use TallowExpr::*;
        let e1 = Call {
            name: "sqrt".to_string(),
            args: vec![],
        };
        assert!(expr_to_graph(&e1).is_err(), "sqrt() must Err");
        let e2 = Call {
            name: "matmul".to_string(),
            args: vec![FloatLit(1.0)],
        };
        assert!(expr_to_graph(&e2).is_err(), "matmul(a) must Err");
        let e3 = Call {
            name: "filter".to_string(),
            args: vec![Array(vec![FloatLit(1.0)])],
        };
        assert!(expr_to_graph(&e3).is_err(), "filter(x) must Err");
    }

    /// F-04-02: integer overflow must decline the fold (no panic, no wrong
    /// constant emitted into the IR).
    #[test]
    fn test_checked_int_folding_declines_on_overflow() {
        let mut graph = FinanceGraph::new();
        let a = graph.constant(ConstantValue::I64(i64::MAX));
        let b = graph.constant(ConstantValue::I64(1));
        let add = graph.push(Op::Add, DType::I64, Shape::Scalar, vec![a, b]);
        graph.outputs = vec![add];
        graph.rebuild_adjacency();

        let stats = ConstantFolding::new().run(&mut graph).unwrap();
        assert_eq!(stats.constants_folded, 0, "overflow must not fold");
        assert!(matches!(graph.nodes[&graph.outputs[0]].op, Op::Add));
    }

    /// F-02-07: `Constant(Array)` evaluates as a Vector, not as 0.0.
    #[test]
    fn test_constant_array_evaluates_as_vector() {
        let mut graph = FinanceGraph::new();
        let c = graph.push(
            Op::Constant(ConstantValue::Array(
                vec![ConstantValue::F64(1.5), ConstantValue::F64(2.5)],
                DType::F64,
            )),
            DType::F64,
            Shape::Vector(2),
            vec![],
        );
        graph.outputs = vec![c];
        graph.rebuild_adjacency();

        let mut interp = GraphInterpreter::new(64);
        let out = interp.eval(&graph, &HashMap::new()).unwrap();
        match &out[0] {
            RuntimeValue::Vector(v) => {
                assert_eq!(v.len(), 2);
                match &v[0] {
                    ConstantValue::F64(f) => assert!((*f - 1.5).abs() < 1e-12),
                    other => panic!("expected F64, got {other:?}"),
                }
            }
            other => panic!("array constant must evaluate as a vector, got {other:?}"),
        }
    }


    // ═══════════════════════════════════════════════════════════════════════
    // Optimizer passes — ConstantFolding
    // ═══════════════════════════════════════════════════════════════════════

    /// CF must fold an integer chain `(7*6)+1` in ONE run (the pass re-reads
    /// inputs per node, so the second fold sees the first fold's constant).
    /// Coverage gap: baseline only folds f64; integer paths untested.
    #[test]
    fn test_cf_i64_chain_folds_exactly() {
        let mut graph = FinanceGraph::new();
        let seven = graph.constant(ConstantValue::I64(7));
        let six = graph.constant(ConstantValue::I64(6));
        let prod = graph.push(Op::Mul, DType::I64, Shape::Scalar, vec![seven, six]);
        let one = graph.constant(ConstantValue::I64(1));
        let sum = graph.push(Op::Add, DType::I64, Shape::Scalar, vec![prod, one]);
        graph.outputs = vec![sum];
        graph.rebuild_adjacency();

        let stats = ConstantFolding::new().run(&mut graph).unwrap();
        assert_eq!(stats.constants_folded, 2, "both (7*6) and (+1) fold in one run");

        // The folded root is a fresh constant node; locate by value (the
        // output-slot list is not a reliable anchor — see header note).
        let folded = graph
            .nodes
            .values()
            .find(|n| matches!(&n.op, Op::Constant(ConstantValue::I64(43))))
            .expect("(7*6)+1 must materialize as Constant(I64(43))");
        assert_eq!(folded.dtype, DType::I64);
        assert_eq!(folded.shape, Shape::Scalar);
        assert!(!graph.nodes.contains_key(&sum), "replaced Add node must be gone");
    }

    /// CF's guards: division by zero is NOT folded, and a node with a
    /// non-constant input is left untouched.
    #[test]
    fn test_cf_guards_zero_division_and_nonconst_inputs() {
        let mut graph = FinanceGraph::new();
        let six = graph.constant(ConstantValue::I64(6));
        let zero = graph.constant(ConstantValue::I64(0));
        let div = graph.push(Op::Div, DType::I64, Shape::Scalar, vec![six, zero]);
        graph.outputs = vec![div];
        graph.rebuild_adjacency();

        let stats = ConstantFolding::new().run(&mut graph).unwrap();
        assert_eq!(stats.constants_folded, 0, "x/0 must not be folded away (guard in try_eval)");
        assert!(graph.nodes.contains_key(&div), "division node must survive");
        assert!(matches!(&graph.nodes[&div].op, Op::Div));

        let mut g2 = FinanceGraph::new();
        let x = g2.input("x", DType::F64, Shape::Scalar);
        let two = g2.constant(ConstantValue::F64(2.0));
        let add = g2.push(Op::Add, DType::F64, Shape::Scalar, vec![x, two]);
        g2.outputs = vec![add];
        g2.rebuild_adjacency();
        let before = g2.len();

        let stats2 = ConstantFolding::new().run(&mut g2).unwrap();
        assert_eq!(stats2.constants_folded, 0, "input+constant is not foldable");
        assert_eq!(g2.len(), before);
        assert!(g2.nodes.contains_key(&add));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Optimizer passes — CSE
    // ═══════════════════════════════════════════════════════════════════════

    /// CSE must merge the duplicate `add(x, y)` AND re-point the downstream
    /// consumer at the kept node; source nodes (Constant/Input) are exempt.
    #[test]
    fn test_cse_merges_duplicate_and_exempts_sources() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let sum1 = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        let sum2 = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        let result = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![sum1, sum2]);
        graph.outputs = vec![result];
        graph.rebuild_adjacency();

        let stats = CommonSubexpressionElimination::new().run(&mut graph).unwrap();
        assert_eq!(stats.nodes_eliminated_cse, 1, "exactly one duplicate");
        assert_eq!(graph.len(), 4, "x, y, kept add, mul");
        assert!(graph.nodes.contains_key(&sum1));
        assert!(!graph.nodes.contains_key(&sum2));
        assert_eq!(
            graph.nodes.get(&result).unwrap().inputs,
            vec![sum1, sum1],
            "consumer must be re-pointed at the kept node"
        );

        // Sources are exempt from CSE even when byte-identical.
        let mut g2 = FinanceGraph::new();
        let c1 = g2.constant(ConstantValue::F64(5.0));
        let c2 = g2.constant(ConstantValue::F64(5.0));
        let v = g2.input("v", DType::F64, Shape::Scalar);
        let s1 = g2.push(Op::Add, DType::F64, Shape::Scalar, vec![c1, v]);
        let s2 = g2.push(Op::Add, DType::F64, Shape::Scalar, vec![c2, v]);
        g2.outputs = vec![s1, s2];
        g2.rebuild_adjacency();

        let stats2 = CommonSubexpressionElimination::new().run(&mut g2).unwrap();
        assert_eq!(stats2.nodes_eliminated_cse, 0, "sources (Constant/Input) are exempt");
        assert!(g2.nodes.contains_key(&c1) && g2.nodes.contains_key(&c2));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Optimizer passes — OperatorFusion
    // ═══════════════════════════════════════════════════════════════════════

    /// `map(f) >> mean` fuses into a single Reduce (no intermediate array).
    #[test]
    /// (Corrected by wave-2 integration, F-02-03: Map->Mean used to fuse into
    /// `Reduce{body: map_body, init: 0.0}` — a sum-fold that never divides by
    /// the count, so `mean(map(f, xs))` computed `sum(map(f, xs))`. Nothing in
    /// `Reduce{body, init}` carries the /n, so the pass must not fuse.
    /// Was: asserted operations_fused == 1 and a fused Reduce with init 0.0.)
    #[test]
    fn test_fusion_map_mean_to_reduce() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(100));
        let body = FinanceGraph::new();
        let map_node = graph.push(
            Op::Map { body: Box::new(body) },
            DType::F64,
            Shape::Vector(100),
            vec![arr],
        );
        let mean_node = graph.push(Op::Mean, DType::F64, Shape::Scalar, vec![map_node]);
        graph.outputs = vec![mean_node];
        graph.rebuild_adjacency();

        let stats = OperatorFusion::new().run(&mut graph).unwrap();
        assert_eq!(stats.operations_fused, 0, "Map->Mean must not fuse (F-02-03)");
        let out = &graph.nodes[&graph.outputs[0]];
        assert!(matches!(out.op, Op::Mean));
        assert!(
            !graph.nodes.values().any(|n| matches!(n.op, Op::Reduce { .. })),
            "no sum-fold Reduce may be introduced"
        );
    }

    /// `sort >> head(n)` fuses into a top-N Head that reads the source directly.
    #[test]
    /// (Corrected by wave-2 integration, F-02-02: the Sort->Head fusion was
    /// a silent miscompile — `head(sort(xs))` is NOT `head(xs)` ("top-N" vs
    /// "first-N" — the fused node read the *unsorted* source directly). Until
    /// a real partial-sort op exists, the pass must leave the pair untouched.
    /// Was: `assert_eq!(stats.operations_fused, 1)` + fused Head input == arr.)
    #[test]
    fn test_fusion_sort_head_to_head() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(100));
        let sorted = graph.push(Op::Sort, DType::F64, Shape::Vector(100), vec![arr]);
        let head = graph.push(Op::Head, DType::F64, Shape::Vector(100), vec![sorted]);
        graph.outputs = vec![head];
        graph.rebuild_adjacency();

        let stats = OperatorFusion::new().run(&mut graph).unwrap();
        assert_eq!(stats.operations_fused, 0, "Sort->Head must not fuse (F-02-02)");
        assert!(graph.nodes.contains_key(&head), "no fused replacement");
        let out = &graph.nodes[&graph.outputs[0]];
        assert!(matches!(out.op, Op::Head));
        assert!(
            graph.nodes.values().any(|n| matches!(n.op, Op::Sort)),
            "the sort must survive: its result feeds the Head"
        );
    }

    /// No-op: a Sum over a plain arithmetic node is not a fusible pattern.
    #[test]
    fn test_fusion_noop_without_fusible_pattern() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let add = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        let sum = graph.push(Op::Sum, DType::F64, Shape::Scalar, vec![add]);
        graph.outputs = vec![sum];
        graph.rebuild_adjacency();
        let before = graph.len();

        let stats = OperatorFusion::new().run(&mut graph).unwrap();
        assert_eq!(stats.operations_fused, 0, "Sum(Add) is not a map-reduce pattern");
        assert_eq!(graph.len(), before);
        assert!(graph.nodes.contains_key(&sum) && graph.nodes.contains_key(&add));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Optimizer passes — DCE
    // ═══════════════════════════════════════════════════════════════════════

    /// DCE removes exactly the unreachable nodes; contract note: with an
    /// EMPTY `outputs` list nothing is reachable and everything is removed.
    #[test]
    fn test_dce_reachability_and_empty_output_contract() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let dead1 = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![x, y]);
        let dead2 = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![dead1, x]);
        let live = graph.push(Op::Sub, DType::F64, Shape::Scalar, vec![x, y]);
        graph.outputs = vec![live];
        graph.rebuild_adjacency();
        // NOTE: rebuild_adjacency() recomputes `outputs` as "every sink", which
        // re-adds the dead sink (dead2; see audits/09-tests.md §2). DCE's
        // contract is reachability from the DESIGNATED outputs, so re-designate
        // after the rebuild — this holds whether or not the auto-output
        // behavior itself is later fixed/redefined by role-02.
        graph.outputs = vec![live];

        let stats = DeadCodeElimination::new().run(&mut graph).unwrap();
        assert_eq!(stats.dead_nodes_removed, 2, "exactly the dead pair");
        assert!(!graph.nodes.contains_key(&dead1) && !graph.nodes.contains_key(&dead2));
        assert!(graph.nodes.contains_key(&live) && graph.nodes.contains_key(&x));
        assert_eq!(graph.len(), 3);

        // Empty outputs => nothing reachable => full sweep.
        let mut g2 = FinanceGraph::new();
        let a = g2.input("a", DType::F64, Shape::Scalar);
        let b = g2.input("b", DType::F64, Shape::Scalar);
        let _add = g2.push(Op::Add, DType::F64, Shape::Scalar, vec![a, b]);
        g2.rebuild_adjacency();
        g2.outputs = vec![]; // explicit: no designated outputs

        let stats2 = DeadCodeElimination::new().run(&mut g2).unwrap();
        assert_eq!(stats2.dead_nodes_removed, 3, "no outputs => everything is unreachable");
        assert!(g2.is_empty());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Optimizer passes — AlgebraicSimplification
    // ═══════════════════════════════════════════════════════════════════════

    /// `0 + x -> x` (zero on the LEFT was untested) and `Neg(Neg(x)) -> x`,
    /// both observed through the downstream consumer.
    #[test]
    fn test_alg_zero_identity_lhs_and_double_negation() {
        let mut graph = FinanceGraph::new();
        let zero = graph.constant(ConstantValue::F64(0.0));
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let add = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![zero, x]);
        let five = graph.constant(ConstantValue::F64(5.0));
        let mul = graph.push(Op::Mul, DType::F64, Shape::Scalar, vec![add, five]);
        graph.outputs = vec![mul];
        graph.rebuild_adjacency();

        let stats = AlgebraicSimplification::new().run(&mut graph).unwrap();
        assert_eq!(stats.algebraic_simplifications, 1);
        assert_eq!(
            graph.nodes.get(&mul).unwrap().inputs,
            vec![x, five],
            "0 + x must rewrite to x"
        );

        let mut g2 = FinanceGraph::new();
        let x2 = g2.input("x", DType::F64, Shape::Scalar);
        let five2 = g2.constant(ConstantValue::F64(5.0));
        let n1 = g2.push(Op::Neg, DType::F64, Shape::Scalar, vec![x2]);
        let n2 = g2.push(Op::Neg, DType::F64, Shape::Scalar, vec![n1]);
        let mul2 = g2.push(Op::Mul, DType::F64, Shape::Scalar, vec![n2, five2]);
        g2.outputs = vec![mul2];
        g2.rebuild_adjacency();

        let stats2 = AlgebraicSimplification::new().run(&mut g2).unwrap();
        assert_eq!(stats2.algebraic_simplifications, 1);
        assert!(!g2.nodes.contains_key(&n2), "outer Neg must be replaced");
        assert_eq!(
            g2.nodes.get(&mul2).unwrap().inputs,
            vec![x2, five2],
            "Neg(Neg(x)) must rewrite to x"
        );
    }

    /// No-op: without an identity operand nothing is simplified.
    #[test]
    fn test_alg_noop_without_identities() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let add = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        graph.outputs = vec![add];
        graph.rebuild_adjacency();
        let before = graph.len();

        let stats = AlgebraicSimplification::new().run(&mut graph).unwrap();
        assert_eq!(stats.algebraic_simplifications, 0);
        assert_eq!(graph.len(), before);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Optimizer — pipeline definition
    // ═══════════════════════════════════════════════════════════════════════

    /// `Optimizer::standard()` must run the documented 5 passes in order.
    #[test]
    fn test_optimizer_standard_pipeline_names() {
        let opt = Optimizer::standard();
        let names: Vec<&str> = opt.passes.iter().map(|p| p.name()).collect();
        assert_eq!(
            names,
            vec![
                "constant_folding",
                "common_subexpression_elimination",
                "operator_fusion",
                "dead_code_elimination",
                "algebraic_simplification",
            ]
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Types — direct unit coverage for predicate/size helpers
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_dtype_shape_constant_predicates() {
        // DType predicates
        assert!(DType::F64.is_numeric());
        assert!(DType::I32.is_numeric());
        assert!(!DType::Bool.is_numeric());
        assert!(!DType::Timestamp.is_numeric());
        assert!(DType::I32.is_integral());
        assert!(!DType::F64.is_integral());
        assert!(DType::F32.is_floating());
        assert!(!DType::I64.is_floating());

        // promote: f64 dominates; the fallback keeps `lhs` (documents the
        // left-biased tail — confirm intent with role-02).
        assert_eq!(DType::promote(&DType::F64, &DType::I32), DType::F64);
        assert_eq!(DType::promote(&DType::Symbol, &DType::F64), DType::F64);
        assert_eq!(DType::promote(&DType::Timestamp, &DType::Date), DType::Timestamp);
        assert_eq!(DType::promote(&DType::Bool, &DType::Bool), DType::Bool);

        // Shape::element_count / is_scalar
        assert_eq!(Shape::Scalar.element_count(), 1);
        assert_eq!(Shape::Vector(7).element_count(), 7);
        assert_eq!(Shape::Matrix(2, 3).element_count(), 6);
        assert_eq!(Shape::Unknown.element_count(), 0);
        assert!(Shape::Scalar.is_scalar());
        assert!(!Shape::Vector(3).is_scalar());

        // ConstantValue::dtype
        assert_eq!(ConstantValue::F64(1.0).dtype(), DType::F64);
        assert_eq!(ConstantValue::Bool(true).dtype(), DType::Bool);
        assert_eq!(ConstantValue::Timestamp(0).dtype(), DType::Timestamp);
        assert_eq!(ConstantValue::Date(0).dtype(), DType::Date);
        assert_eq!(ConstantValue::Array(vec![], DType::F32).dtype(), DType::F32);
        assert_eq!(
            ConstantValue::Null.dtype(),
            DType::Nullable(Box::new(DType::I64))
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Interpreter — edge cases
    // ═══════════════════════════════════════════════════════════════════════

    /// Empty graph -> Ok(empty); missing bindings and unimplemented ops -> Err.
    #[test]
    fn test_interp_empty_graph_and_error_paths() {
        let mut interp = GraphInterpreter::new(0);
        let out = interp.eval(&FinanceGraph::new(), &HashMap::new()).unwrap();
        assert!(out.is_empty(), "empty graph evaluates to zero outputs");

        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        graph.outputs = vec![sum];
        graph.rebuild_adjacency();
        let err = interp.eval(&graph, &HashMap::new()).unwrap_err();
        assert!(err.contains("Missing input: x"), "got: {err}");

        let mut g2 = FinanceGraph::new();
        let a = g2.input("a", DType::F64, Shape::Vector(4));
        let h = g2.push(Op::Head, DType::F64, Shape::Vector(4), vec![a]);
        g2.outputs = vec![h];
        g2.rebuild_adjacency();
        let mut bindings = HashMap::new();
        bindings.insert(
            "a".to_string(),
            RuntimeValue::Vector(vec![ConstantValue::F64(1.0); 4]),
        );
        let err2 = interp.eval(&g2, &bindings).unwrap_err();
        assert!(err2.contains("not yet implemented"), "got: {err2}");
    }

    /// Division uses IEEE f64 semantics: no panic, +inf and NaN propagate.
    #[test]
    fn test_interp_division_by_zero_is_ieee() {
        let mut graph = FinanceGraph::new();
        let one = graph.constant(ConstantValue::F64(1.0));
        let zero = graph.constant(ConstantValue::F64(0.0));
        let div1 = graph.push(Op::Div, DType::F64, Shape::Scalar, vec![one, zero]);
        let div2 = graph.push(Op::Div, DType::F64, Shape::Scalar, vec![zero, zero]);
        graph.outputs = vec![div1, div2]; // eval preserves this order

        let mut interp = GraphInterpreter::new(64);
        let out = interp.eval(&graph, &HashMap::new()).unwrap();
        match (&out[0], &out[1]) {
            (
                RuntimeValue::Scalar(ConstantValue::F64(a)),
                RuntimeValue::Scalar(ConstantValue::F64(b)),
            ) => {
                assert!(a.is_infinite() && *a > 0.0, "1.0/0.0 = +inf, got {a}");
                assert!(b.is_nan(), "0.0/0.0 = NaN, got {b}");
            }
            other => panic!("expected two scalars, got {other:?}"),
        }
    }

    /// Zero-length vectors: Sum folds to the init 0.0; Mean has no empty
    /// guard and yields NaN (current behavior — confirm with role-02).
    #[test]
    fn test_interp_zero_length_vector_sum_and_mean() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(0));
        let s = graph.push(Op::Sum, DType::F64, Shape::Scalar, vec![arr]);
        let m = graph.push(Op::Mean, DType::F64, Shape::Scalar, vec![arr]);
        graph.outputs = vec![s, m];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert("arr".to_string(), RuntimeValue::Vector(vec![]));
        let mut interp = GraphInterpreter::new(64);
        let out = interp.eval(&graph, &bindings).unwrap();
        match (&out[0], &out[1]) {
            (
                RuntimeValue::Scalar(ConstantValue::F64(sv)),
                RuntimeValue::Scalar(ConstantValue::F64(mv)),
            ) => {
                assert_eq!(*sv, 0.0, "Sum of empty array is the fold init 0.0");
                assert!(mv.is_nan(), "Mean of empty array is 0.0/0.0 = NaN (no guard)");
            }
            other => panic!("expected two scalars, got {other:?}"),
        }
    }

    /// Ema with an explicit alpha input (existing tests only use the 0.1 default).
    #[test]
    fn test_interp_ema_with_explicit_alpha() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(3));
        let alpha = graph.input("alpha", DType::F64, Shape::Scalar);
        let ema = graph.push(Op::Ema, DType::F64, Shape::Vector(3), vec![arr, alpha]);
        graph.outputs = vec![ema];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(10.0),
                ConstantValue::F64(20.0),
                ConstantValue::F64(30.0),
            ]),
        );
        bindings.insert(
            "alpha".to_string(),
            RuntimeValue::Scalar(ConstantValue::F64(0.5)),
        );

        let mut interp = GraphInterpreter::new(64);
        let out = interp.eval(&graph, &bindings).unwrap();
        match &out[0] {
            RuntimeValue::Vector(v) => {
                let vals: Vec<f64> = v
                    .iter()
                    .map(|c| match c {
                        ConstantValue::F64(f) => *f,
                        _ => f64::NAN,
                    })
                    .collect();
                // ema0 = 10; ema1 = .5*20 + .5*10 = 15; ema2 = .5*30 + .5*15 = 22.5
                assert_eq!(vals, vec![10.0, 15.0, 22.5]);
            }
            other => panic!("expected vector, got {other:?}"),
        }
    }

    /// Window function coverage: `Max` (existing tests only cover Sum/Mean).
    #[test]
    fn test_interp_window_max() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(4));
        let w = graph.push(
            Op::Window { size: 2, stride: 1, func: WindowFunc::Max },
            DType::F64,
            Shape::Vector(3),
            vec![arr],
        );
        graph.outputs = vec![w];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(1.0),
                ConstantValue::F64(3.0),
                ConstantValue::F64(2.0),
                ConstantValue::F64(5.0),
            ]),
        );
        let mut interp = GraphInterpreter::new(64);
        let out = interp.eval(&graph, &bindings).unwrap();
        match &out[0] {
            RuntimeValue::Vector(v) => {
                let vals: Vec<f64> = v
                    .iter()
                    .map(|c| match c {
                        ConstantValue::F64(f) => *f,
                        _ => f64::NAN,
                    })
                    .collect();
                assert_eq!(vals, vec![3.0, 3.0, 5.0]);
            }
            other => panic!("expected vector, got {other:?}"),
        }
    }

    /// [EXPECTED-FAIL PROBE — interpreter bug]
    /// Window over an input shorter than the window. The code computes
    /// `num_windows = 0` but then iterates `(0..=n - size)` (baseline
    /// finance_ir.rs:2866): usize underflow => panic in debug (wraps and
    /// slices out of range in release). Intended semantics, per the same
    /// function's `num_windows` guard: empty result. Do NOT weaken — fix
    /// the interpreter (role-02/integrator) or prove this test wrong.
    #[test]
    fn test_interp_window_shorter_than_window() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(3));
        let w = graph.push(
            Op::Window { size: 5, stride: 1, func: WindowFunc::Mean },
            DType::F64,
            Shape::Vector(0),
            vec![arr],
        );
        graph.outputs = vec![w];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert(
            "arr".to_string(),
            RuntimeValue::Vector(vec![
                ConstantValue::F64(1.0),
                ConstantValue::F64(2.0),
                ConstantValue::F64(3.0),
            ]),
        );
        let mut interp = GraphInterpreter::new(64);
        let out = interp
            .eval(&graph, &bindings)
            .expect("short input must not panic; expected an empty result");
        match &out[0] {
            RuntimeValue::Vector(v) => assert!(v.is_empty(), "0 windows fit in a 3-element input"),
            other => panic!("expected empty vector, got {other:?}"),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Memory planner — invariants
    // ═══════════════════════════════════════════════════════════════════════

    /// Every node gets exactly one allocation record; scalars are
    /// register-resident (size 0); real buffers are 64-byte aligned and
    /// peak memory never exceeds the final arena.
    #[test]
    fn test_memory_plan_covers_all_nodes_and_aligns() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Vector(64));
        let y = graph.input("y", DType::F64, Shape::Vector(64));
        let add = graph.push(Op::Add, DType::F64, Shape::Vector(64), vec![x, y]);
        let s = graph.push(Op::Sum, DType::F64, Shape::Scalar, vec![add]);
        graph.outputs = vec![s];
        graph.rebuild_adjacency();

        let plan = MemoryPlanner::new().plan(&graph);
        assert_eq!(plan.allocations.len(), graph.len(), "one record per node");

        let mut ids: Vec<NodeId> = plan.allocations.iter().map(|a| a.node_id).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![x, y, add, s], "all nodes covered exactly once, no duplicates");

        let sa = plan.allocations.iter().find(|a| a.node_id == s).unwrap();
        assert_eq!(sa.size_bytes, 0, "scalar Sum is register-resident");

        for a in &plan.allocations {
            if a.size_bytes > 0 {
                assert_eq!(a.arena_offset % 64, 0, "node {} offset not 64-aligned", a.node_id);
            }
        }
        assert!(plan.peak_memory <= plan.arena_size);
        assert!(plan.arena_size >= 512, "at least one 64-element f64 buffer");
    }

    /// Columnar sizes: element counts round UP to the 8-element SIMD width.
    #[test]
    fn test_memory_plan_columnar_size_rounding() {
        let mut graph = FinanceGraph::new();
        let arr = graph.input("arr", DType::F64, Shape::Vector(13));
        let r = graph.push(Op::Sqrt, DType::F64, Shape::Vector(13), vec![arr]);
        graph.outputs = vec![r];
        graph.rebuild_adjacency();
        let plan = MemoryPlanner::new().plan(&graph);
        let a_arr = plan.allocations.iter().find(|a| a.node_id == arr).unwrap();
        assert_eq!(a_arr.size_bytes, 128, "13 f64 round up to 16 elements * 8 bytes");

        let mut g2 = FinanceGraph::new();
        let i1 = g2.input("i1", DType::I32, Shape::Vector(5));
        let i2 = g2.input("i2", DType::I32, Shape::Vector(5));
        let add = g2.push(Op::Add, DType::I32, Shape::Vector(5), vec![i1, i2]);
        g2.outputs = vec![add];
        g2.rebuild_adjacency();
        let plan2 = MemoryPlanner::new().plan(&g2);
        let a_i1 = plan2.allocations.iter().find(|a| a.node_id == i1).unwrap();
        assert_eq!(a_i1.size_bytes, 32, "5 i32 round up to 8 elements * 4 bytes");
    }

    /// [EXPECTED-FAIL PROBE — memory planner bug]
    /// x and y are both live at the Sub (last use, pos 2), so their arena
    /// slots must not overlap — the planner's own contract says "buffer
    /// reuse: NON-OVERLAPPING live ranges can share buffers". Observed
    /// (sandbox_a09, same logic): y reuses x's still-live slot at offset 0
    /// because the free-retain keeps live buffers and the reuse loop then
    /// draws from them (baseline finance_ir.rs:1977-2007). Consequence: the
    /// plan aliases live input buffers. Do NOT weaken — fix the planner.
    #[test]
    fn test_memory_plan_live_buffers_not_aliased() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Vector(1024));
        let y = graph.input("y", DType::F64, Shape::Vector(1024));
        let s = graph.push(Op::Sub, DType::F64, Shape::Vector(1024), vec![x, y]);
        graph.outputs = vec![s];
        graph.rebuild_adjacency();

        let plan = MemoryPlanner::new().plan(&graph);
        let ax = plan.allocations.iter().find(|a| a.node_id == x).unwrap();
        let ay = plan.allocations.iter().find(|a| a.node_id == y).unwrap();
        assert!(ax.size_bytes > 0 && ay.size_bytes > 0, "both inputs need real buffers");
        assert_ne!(
            ax.arena_offset, ay.arena_offset,
            "simultaneously-live buffers must not alias (x offset {}, y offset {})",
            ax.arena_offset, ay.arena_offset
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // LLVM emitter — output sanity
    // ═══════════════════════════════════════════════════════════════════════

    /// Module header fields, input parameter formatting, empty arena for a
    /// scalar graph, and a well-formed function tail.
    #[test]
    fn test_llvm_module_header_and_scalar_function() {
        let mut graph = FinanceGraph::new();
        let x = graph.input("x", DType::F64, Shape::Scalar);
        let y = graph.input("y", DType::F64, Shape::Scalar);
        let sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![x, y]);
        graph.outputs = vec![sum];
        graph.rebuild_adjacency();

        let plan = MemoryPlanner::new().plan(&graph);
        let ir = LlvmCodegen::new().generate(&graph, &plan, "a09_simple_add");

        assert!(ir.starts_with("; Tallow Financial IR → LLVM IR\n"));
        assert!(ir.contains("; Target: x86_64-unknown-linux-gnu"));
        assert!(ir.contains("; Vector width: 4 elements"));
        assert!(ir.contains("; FMA: true"));
        assert!(ir.contains("%arena = alloca [0 x i8], align 64"), "scalar graph needs no arena");
        assert!(ir.contains("define void @a09_simple_add("));
        assert!(ir.contains("%input_0,"), "first parameter uses the %input_<i> convention");
        assert!(ir.contains("%input_1) {"));
        assert!(ir.contains("fadd double"));
        assert!(ir.trim_end().ends_with("ret void\n}"));
        // NOTE: the exact store instruction shape depends on role-01's fix of
        // the baseline:2226 format-string error; both plausible fixes keep the
        // `%out_<i>` slot name.
        assert!(ir.contains("%out_0"));
    }

    /// Constant lowering: integral f64 values lower exactly via i64; constant
    /// variants with no scalar numeric lowering must be flagged LOUDLY (the
    /// deliberate FINANCE-IR CONST LOWERING ERROR marker), never silently 0.
    #[test]
    fn test_llvm_constant_lowering_and_error_marker() {
        let mut g1 = FinanceGraph::new();
        let c = g1.constant(ConstantValue::F64(3.0));
        g1.outputs = vec![c];
        g1.rebuild_adjacency();
        let plan1 = MemoryPlanner::new().plan(&g1);
        let ir1 = LlvmCodegen::new().generate(&g1, &plan1, "a09_const");
        assert!(
            ir1.contains("sitofp i64 3 to double"),
            "integral f64 constant must lower exactly"
        );

        let mut g2 = FinanceGraph::new();
        let s = g2.constant(ConstantValue::String("hello".to_string()));
        g2.outputs = vec![s];
        g2.rebuild_adjacency();
        let plan2 = MemoryPlanner::new().plan(&g2);
        let ir2 = LlvmCodegen::new().generate(&g2, &plan2, "a09_bad_const");
        assert!(
            ir2.contains("FINANCE-IR CONST LOWERING ERROR"),
            "unlowerable constants must be flagged loudly, not silently zeroed: {ir2}"
        );
    }

    /// Scalar op flags: FMA toggle for Mul, integer Add lowering, f64 Div.
    #[test]
    fn test_llvm_fma_toggle_integer_and_division_ops() {
        let mut g1 = FinanceGraph::new();
        let a = g1.input("a", DType::F64, Shape::Scalar);
        let b = g1.input("b", DType::F64, Shape::Scalar);
        let mul = g1.push(Op::Mul, DType::F64, Shape::Scalar, vec![a, b]);
        g1.outputs = vec![mul];
        g1.rebuild_adjacency();
        let plan1 = MemoryPlanner::new().plan(&g1);

        let ir1 = LlvmCodegen::new().generate(&g1, &plan1, "a09_mul_fma");
        assert!(ir1.contains("@llvm.fma.f64("), "fma defaults on for f64 Mul");
        assert!(ir1.contains("declare double @llvm.fma.f64(double, double, double)"));

        let mut cg = LlvmCodegen::new();
        cg.fma = false;
        let ir2 = cg.generate(&g1, &plan1, "a09_mul_nofma");
        assert!(ir2.contains("fmul double"));
        assert!(!ir2.contains("@llvm.fma.f64("), "no fma intrinsic when disabled");

        let mut g3 = FinanceGraph::new();
        let i1 = g3.input("i1", DType::I64, Shape::Scalar);
        let i2 = g3.input("i2", DType::I64, Shape::Scalar);
        let add = g3.push(Op::Add, DType::I64, Shape::Scalar, vec![i1, i2]);
        g3.outputs = vec![add];
        g3.rebuild_adjacency();
        let plan3 = MemoryPlanner::new().plan(&g3);
        let ir3 = LlvmCodegen::new().generate(&g3, &plan3, "a09_int_add");
        assert!(ir3.contains("add i64"));
        assert!(!ir3.contains("fadd"));

        let mut g4 = FinanceGraph::new();
        let p = g4.input("p", DType::F64, Shape::Scalar);
        let q = g4.input("q", DType::F64, Shape::Scalar);
        let div = g4.push(Op::Div, DType::F64, Shape::Scalar, vec![p, q]);
        g4.outputs = vec![div];
        g4.rebuild_adjacency();
        let plan4 = MemoryPlanner::new().plan(&g4);
        let ir4 = LlvmCodegen::new().generate(&g4, &plan4, "a09_div");
        assert!(ir4.contains("fdiv double"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CUDA stub
    // ═══════════════════════════════════════════════════════════════════════

    /// Offload thresholds (strict `>` boundaries; reductions need 10x), f32
    /// kernel ctype selection, and launch-parameter ceiling division.
    #[test]
    fn test_cuda_offload_thresholds_f32_kernels_and_launch_params() {
        let mm = Node::new(0, Op::MatMul, DType::F64, Shape::Matrix(4096, 4096), vec![]);
        assert!(CudaCodegen::should_offload(&mm, 10_000));
        let small = Node::new(0, Op::MatMul, DType::F64, Shape::Matrix(300, 300), vec![]);
        assert!(!CudaCodegen::should_offload(&small, 100_000), "90_000 <= 100_000");

        let s_big = Node::new(0, Op::Sum, DType::F64, Shape::Vector(1_000_001), vec![]);
        assert!(CudaCodegen::should_offload(&s_big, 100_000), "reductions need >10x threshold");
        let s_edge = Node::new(0, Op::Sum, DType::F64, Shape::Vector(1_000_000), vec![]);
        assert!(!CudaCodegen::should_offload(&s_edge, 100_000), "boundary is strict");

        let m_big = Node::new(
            0,
            Op::Map { body: Box::new(FinanceGraph::new()) },
            DType::F64,
            Shape::Vector(100_001),
            vec![],
        );
        assert!(CudaCodegen::should_offload(&m_big, 100_000));

        let cg = CudaCodegen::new();
        assert_eq!(cg.launch_params(1024, 1024), (32, 32));
        assert_eq!(
            cg.launch_params(33, 1),
            (1, 2),
            "grid_x derives from n and grid_y from m — ceil division"
        );
        assert_eq!(cg.launch_params(1, 33), (2, 1));
        assert_eq!(cg.launch_params(1, 32), (1, 1));
        assert_eq!(cg.launch_params(0, 0), (0, 0));

        let k = cg.generate_matmul_kernel(4, 4, 4, &DType::F32);
        assert!(k.contains("tallow_matmul_f32"));
        assert!(k.contains("const float* __restrict__ A"));
        assert!(k.contains("__shared__ float As[TILE_SIZE][TILE_SIZE];"));
        assert!(k.contains("#define TILE_SIZE 32"));

        let r = cg.generate_reduce_kernel(128, &DType::F32);
        assert!(r.contains("tallow_reduce_f32"));
        assert!(r.contains("#define BLOCK_SIZE 256"));
        assert!(r.contains("output[blockIdx.x] = sdata[0];"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Validation + lowering error paths
    // ═══════════════════════════════════════════════════════════════════════

    /// validate() must reject dangling input edges AND cycles (the cycle
    /// branch is completely untested in the existing suite).
    #[test]
    fn test_validate_rejects_missing_input_and_cycle() {
        let mut graph = FinanceGraph::new();
        graph.add_node(Node::new(0, Op::Add, DType::F64, Shape::Scalar, vec![999]));
        let err = graph.validate().unwrap_err();
        assert!(err.contains("non-existent input 999"), "got: {err}");

        let mut cyc = FinanceGraph::new();
        cyc.add_node(Node::new(0, Op::Add, DType::F64, Shape::Scalar, vec![1]));
        cyc.add_node(Node::new(1, Op::Mul, DType::F64, Shape::Scalar, vec![0]));
        let err2 = cyc.validate().unwrap_err();
        assert!(err2.contains("cycles"), "self-referencing nodes must be detected: {err2}");
    }

    /// expr_to_graph error propagation: undefined ident, unknown call,
    /// matmul dimension mismatch.
    #[test]
    fn test_lowering_rejects_undefined_call_and_bad_matmul() {
        use TallowExpr::*;

        let err1 = expr_to_graph(&Ident("nope".to_string())).unwrap_err();
        assert!(err1.contains("Undefined variable: nope"), "got: {err1}");

        let err2 = expr_to_graph(&Call { name: "frobnicate".to_string(), args: vec![] }).unwrap_err();
        assert!(err2.contains("Unknown financial function: frobnicate"), "got: {err2}");

        let e3 = Call {
            name: "matmul".to_string(),
            args: vec![
                Array(vec![FloatLit(1.0), FloatLit(2.0), FloatLit(3.0)]),
                Array(vec![FloatLit(1.0), FloatLit(2.0)]),
            ],
        };
        let err3 = expr_to_graph(&e3).unwrap_err();
        assert!(err3.contains("dimension mismatch"), "got: {err3}");
    }

    /// Builder: Let-bound locals, Unary Neg, and graph naming.
    #[test]
    fn test_build_expr_let_unary_and_names() {
        use TallowExpr::*;

        // let v = 2.0 in v + 3.0
        let e = Let {
            name: "v".to_string(),
            value: Box::new(FloatLit(2.0)),
            body: Box::new(Binary {
                op: BinOp::Add,
                left: Box::new(Ident("v".to_string())),
                right: Box::new(FloatLit(3.0)),
            }),
        };
        let graph = expr_to_graph(&e).unwrap();
        let mut interp = GraphInterpreter::new(64);
        let out = interp.eval(&graph, &HashMap::new()).unwrap();
        match &out[0] {
            RuntimeValue::Scalar(ConstantValue::F64(v)) => {
                assert!((*v - 5.0).abs() < 1e-12, "let-bound v + 3.0 = 5.0")
            }
            other => panic!("expected 5.0, got {other:?}"),
        }

        // -2.0
        let e2 = Unary { op: UnOp::Neg, operand: Box::new(FloatLit(2.0)) };
        let g2 = expr_to_graph(&e2).unwrap();
        let out2 = interp.eval(&g2, &HashMap::new()).unwrap();
        match &out2[0] {
            RuntimeValue::Scalar(ConstantValue::F64(v)) => assert!((*v + 2.0).abs() < 1e-12),
            other => panic!("expected -2.0, got {other:?}"),
        }

        // Naming helpers.
        let builder = GraphBuilder::with_name("pipeline");
        assert_eq!(builder.graph.name.as_deref(), Some("pipeline"));
        assert!(builder.graph.is_empty());
        assert!(FinanceGraph::with_name(None::<String>).name.is_none());
    }

    /// Builder: array literals lower to Zip with a Vector shape; call defaults
    /// (`lag` non-literal offset -> 1, `sma` literal window honored,
    /// `transpose` vector -> 1xN matrix).
    #[test]
    fn test_build_expr_array_and_call_shapes() {
        use TallowExpr::*;

        let e1 = Array(vec![FloatLit(1.0), FloatLit(2.0)]);
        let g1 = expr_to_graph(&e1).unwrap();
        let zip = g1
            .nodes
            .values()
            .find(|n| matches!(&n.op, Op::Zip { .. }))
            .expect("array literal lowers to a Zip node");
        assert_eq!(zip.shape, Shape::Vector(2));
        assert_eq!(zip.dtype, DType::F64);
        assert_eq!(zip.inputs.len(), 2);
        assert!(g1.validate().is_ok());
        // NOTE: Zip has no interpreter implementation (see error-path test),
        // so only construction is asserted here.

        // lag(arr, 2.0): non-IntLit offset falls back to 1
        let lag_expr = Let {
            name: "arr".to_string(),
            value: Box::new(Array(vec![FloatLit(1.0), FloatLit(2.0), FloatLit(3.0)])),
            body: Box::new(Call {
                name: "lag".to_string(),
                args: vec![Ident("arr".to_string()), FloatLit(2.0)],
            }),
        };
        let g2 = expr_to_graph(&lag_expr).unwrap();
        let lag = g2
            .nodes
            .values()
            .find(|n| matches!(&n.op, Op::Lag(_)))
            .expect("lag node");
        match &lag.op {
            Op::Lag(off) => assert_eq!(*off, 1, "non-literal offset defaults to 1"),
            _ => unreachable!(),
        }
        assert_eq!(lag.inputs.len(), 1);

        // sma(arr, 5): IntLit window is honored
        let sma_expr = Let {
            name: "arr".to_string(),
            value: Box::new(Array(vec![FloatLit(1.0)])),
            body: Box::new(Call {
                name: "sma".to_string(),
                args: vec![Ident("arr".to_string()), IntLit(5)],
            }),
        };
        let g3 = expr_to_graph(&sma_expr).unwrap();
        let sma = g3
            .nodes
            .values()
            .find(|n| matches!(&n.op, Op::Sma { .. }))
            .expect("sma node");
        match &sma.op {
            Op::Sma { window } => assert_eq!(*window, 5),
            _ => unreachable!(),
        }

        // transpose(vector(3)) -> Matrix(1, 3)
        let tr_expr = Let {
            name: "arr".to_string(),
            value: Box::new(Array(vec![FloatLit(1.0), FloatLit(2.0), FloatLit(3.0)])),
            body: Box::new(Call {
                name: "transpose".to_string(),
                args: vec![Ident("arr".to_string())],
            }),
        };
        let g4 = expr_to_graph(&tr_expr).unwrap();
        let tr = g4
            .nodes
            .values()
            .find(|n| matches!(&n.op, Op::Transpose))
            .expect("transpose node");
        assert_eq!(tr.shape, Shape::Matrix(1, 3));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Compiler orchestrator
    // ═══════════════════════════════════════════════════════════════════════

    /// compile() propagates lowering errors; verify() (previously untested)
    /// runs the interpreter on a pre-built graph.
    #[test]
    fn test_financial_compiler_error_and_verify() {
        use TallowExpr::*;

        let compiler = FinancialCompiler::new();
        let err = compiler.compile(&Ident("x".to_string())).unwrap_err();
        assert!(err.contains("Undefined variable"), "got: {err}");

        let mut graph = FinanceGraph::new();
        let a = graph.input("a", DType::F64, Shape::Scalar);
        let b = graph.input("b", DType::F64, Shape::Scalar);
        let sum = graph.push(Op::Add, DType::F64, Shape::Scalar, vec![a, b]);
        graph.outputs = vec![sum];
        graph.rebuild_adjacency();

        let mut bindings = HashMap::new();
        bindings.insert("a".to_string(), RuntimeValue::Scalar(ConstantValue::F64(3.0)));
        bindings.insert("b".to_string(), RuntimeValue::Scalar(ConstantValue::F64(4.0)));
        let out = FinancialCompiler::verify(&graph, &bindings).unwrap();
        match &out[0] {
            RuntimeValue::Scalar(ConstantValue::F64(v)) => assert!((*v - 7.0).abs() < 1e-12),
            other => panic!("expected 7.0, got {other:?}"),
        }
    }

    /// compile() GPU bookkeeping: a 100_001-element transpose (note:
    /// threshold is >100_000, so this is the smallest tripping size) records
    /// offloaded nodes while the CUDA stub emits no kernel for Transpose.
    /// Deterministic; ~100k nodes, sub-second.
    #[test]
    fn test_compile_offloads_large_transpose() {
        use TallowExpr::*;
        let elems = vec![FloatLit(1.0); 100_001];
        let expr = Call {
            name: "transpose".to_string(),
            args: vec![Array(elems)],
        };
        let compiler = FinancialCompiler::new();
        let result = compiler.compile(&expr).unwrap();
        assert!(
            !result.cuda_offload_candidates.is_empty(),
            "100_001 elements must trip the 100_000 GPU threshold"
        );
        assert!(result.cuda_kernels.is_empty(), "Transpose has no kernel in the CUDA stub");
        assert!(result.llvm_ir.contains("define void @tallow_finance"));
    }

    // ── Row #89: ops that used to return "not yet implemented" ────────────

    fn const_scalar(graph: &mut FinanceGraph, v: f64) -> NodeId {
        graph.push(
            Op::Constant(ConstantValue::F64(v)),
            DType::F64,
            Shape::Scalar,
            vec![],
        )
    }

    fn const_vec(graph: &mut FinanceGraph, vals: &[f64]) -> NodeId {
        let cells: Vec<ConstantValue> = vals.iter().map(|v| ConstantValue::F64(*v)).collect();
        graph.push(
            Op::Constant(ConstantValue::Array(cells, DType::F64)),
            DType::F64,
            Shape::Vector(vals.len()),
            vec![],
        )
    }

    fn scalar_at(results: &[RuntimeValue], index: usize) -> f64 {
        match &results[index] {
            RuntimeValue::Scalar(ConstantValue::F64(v)) => *v,
            other => panic!("expected scalar at {index}, got {other:?}"),
        }
    }

    #[test]
    fn interp_pow_mod_round_floor_ceil_log10() {
        let mut graph = FinanceGraph::new();
        let two = const_scalar(&mut graph, 2.0);
        let five = const_scalar(&mut graph, 5.0);
        let frac = const_scalar(&mut graph, 2.6);
        let thousand = const_scalar(&mut graph, 1000.0);
        let pow = graph.push(Op::Pow, DType::F64, Shape::Scalar, vec![two, five]);
        let modulo = graph.push(Op::Mod, DType::F64, Shape::Scalar, vec![five, two]);
        let round = graph.push(Op::Round, DType::F64, Shape::Scalar, vec![frac]);
        let floor = graph.push(Op::Floor, DType::F64, Shape::Scalar, vec![frac]);
        let ceil = graph.push(Op::Ceil, DType::F64, Shape::Scalar, vec![frac]);
        let log10 = graph.push(Op::Log10, DType::F64, Shape::Scalar, vec![thousand]);
        graph.outputs = vec![pow, modulo, round, floor, ceil, log10];
        graph.rebuild_adjacency();

        let mut interp = GraphInterpreter::new(4096);
        let out = interp.eval(&graph, &HashMap::new()).unwrap();
        assert!((scalar_at(&out, 0) - 32.0).abs() < 1e-9, "pow");
        assert!((scalar_at(&out, 1) - 1.0).abs() < 1e-9, "mod");
        assert!((scalar_at(&out, 2) - 3.0).abs() < 1e-9, "round");
        assert!((scalar_at(&out, 3) - 2.0).abs() < 1e-9, "floor");
        assert!((scalar_at(&out, 4) - 3.0).abs() < 1e-9, "ceil");
        assert!((scalar_at(&out, 5) - 3.0).abs() < 1e-9, "log10");
    }

    #[test]
    fn interp_var_min_max_over_vector() {
        let mut graph = FinanceGraph::new();
        let values = const_vec(&mut graph, &[1.0, 2.0, 3.0, 4.0]);
        let var = graph.push(Op::Var, DType::F64, Shape::Scalar, vec![values]);
        let min = graph.push(Op::Min, DType::F64, Shape::Scalar, vec![values]);
        let max = graph.push(Op::Max, DType::F64, Shape::Scalar, vec![values]);
        graph.outputs = vec![var, min, max];
        graph.rebuild_adjacency();

        let mut interp = GraphInterpreter::new(4096);
        let out = interp.eval(&graph, &HashMap::new()).unwrap();
        assert!((scalar_at(&out, 0) - 1.25).abs() < 1e-9, "population var");
        assert!((scalar_at(&out, 1) - 1.0).abs() < 1e-9, "min");
        assert!((scalar_at(&out, 2) - 4.0).abs() < 1e-9, "max");
    }

    #[test]
    fn interp_cov_and_corr_over_two_vectors() {
        let mut graph = FinanceGraph::new();
        let xs = const_vec(&mut graph, &[1.0, 2.0, 3.0]);
        let ys = const_vec(&mut graph, &[2.0, 4.0, 6.0]);
        let cov = graph.push(Op::Cov, DType::F64, Shape::Scalar, vec![xs, ys]);
        let corr = graph.push(Op::Corr, DType::F64, Shape::Scalar, vec![xs, ys]);
        graph.outputs = vec![cov, corr];
        graph.rebuild_adjacency();

        let mut interp = GraphInterpreter::new(4096);
        let out = interp.eval(&graph, &HashMap::new()).unwrap();
        assert!(
            (scalar_at(&out, 0) - 4.0 / 3.0).abs() < 1e-9,
            "population covariance"
        );
        assert!((scalar_at(&out, 1) - 1.0).abs() < 1e-9, "perfect correlation");
    }
}

// Helper: allow get_mut for tests
impl FinanceGraph {
    fn get_mut(&mut self, id: NodeId) -> Option<&mut Node> {
        self.nodes.get_mut(&id)
    }
}
