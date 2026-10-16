//! Frame tree parsing for iframe traversal.
//!
//! Provides FrameInfo for describing frames in the page's frame tree,
//! and parse_frame_tree for converting CDP Page.getFrameTree responses.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Information about a frame in the page's frame tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameInfo {
    /// CDP frame ID.
    pub id: String,
    /// Frame's current URL.
    pub url: String,
    /// Frame name (from `<iframe name="...">`) -- empty if unnamed.
    pub name: String,
    /// Parent frame ID -- None for the main frame.
    pub parent_id: Option<String>,
}

/// Parse a CDP `Page.getFrameTree` response into a flat list of FrameInfo.
///
/// The response has shape:
/// ```json
/// { "frameTree": { "frame": { "id", "url", "name", ... }, "childFrames": [...] } }
/// ```
///
/// Recursively walks childFrames, collecting FrameInfo for each.
pub fn parse_frame_tree(tree: &Value) -> Vec<FrameInfo> {
    let mut frames = Vec::new();

    // The root may be the full response or just the frameTree node
    let frame_tree = tree.get("frameTree").unwrap_or(tree);

    collect_frames(frame_tree, None, &mut frames);
    frames
}

/// Recursively collect frames from a frameTree node.
fn collect_frames(node: &Value, parent_id: Option<&str>, out: &mut Vec<FrameInfo>) {
    if let Some(frame) = node.get("frame") {
        let id = frame
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let url = frame
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let name = frame
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        out.push(FrameInfo {
            id: id.clone(),
            url,
            name,
            parent_id: parent_id.map(|s| s.to_string()),
        });

        // Process child frames
        if let Some(children) = node.get("childFrames").and_then(|c| c.as_array()) {
            for child in children {
                collect_frames(child, Some(&id), out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_frame_info_construction() {
        let info = FrameInfo {
            id: "F1".to_string(),
            url: "https://example.com".to_string(),
            name: "main".to_string(),
            parent_id: None,
        };
        assert_eq!(info.id, "F1");
        assert_eq!(info.url, "https://example.com");
        assert_eq!(info.name, "main");
        assert!(info.parent_id.is_none());
    }

    #[test]
    fn test_frame_info_with_parent() {
        let info = FrameInfo {
            id: "F2".to_string(),
            url: "https://example.com/iframe".to_string(),
            name: "child-frame".to_string(),
            parent_id: Some("F1".to_string()),
        };
        assert_eq!(info.parent_id, Some("F1".to_string()));
    }

    #[test]
    fn test_parse_frame_tree_single_frame() {
        let tree = json!({
            "frameTree": {
                "frame": {
                    "id": "MAIN",
                    "url": "https://example.com",
                    "name": ""
                }
            }
        });

        let frames = parse_frame_tree(&tree);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].id, "MAIN");
        assert_eq!(frames[0].url, "https://example.com");
        assert!(frames[0].parent_id.is_none());
    }

    #[test]
    fn test_parse_frame_tree_with_children() {
        let tree = json!({
            "frameTree": {
                "frame": {
                    "id": "MAIN",
                    "url": "https://example.com",
                    "name": ""
                },
                "childFrames": [
                    {
                        "frame": {
                            "id": "CHILD1",
                            "url": "https://example.com/iframe1",
                            "name": "frame-one"
                        }
                    },
                    {
                        "frame": {
                            "id": "CHILD2",
                            "url": "https://example.com/iframe2",
                            "name": "frame-two"
                        }
                    }
                ]
            }
        });

        let frames = parse_frame_tree(&tree);
        assert_eq!(frames.len(), 3);

        // Main frame
        assert_eq!(frames[0].id, "MAIN");
        assert!(frames[0].parent_id.is_none());

        // Child 1
        assert_eq!(frames[1].id, "CHILD1");
        assert_eq!(frames[1].name, "frame-one");
        assert_eq!(frames[1].parent_id, Some("MAIN".to_string()));

        // Child 2
        assert_eq!(frames[2].id, "CHILD2");
        assert_eq!(frames[2].name, "frame-two");
        assert_eq!(frames[2].parent_id, Some("MAIN".to_string()));
    }

    #[test]
    fn test_parse_frame_tree_nested_grandchild() {
        let tree = json!({
            "frameTree": {
                "frame": {
                    "id": "MAIN",
                    "url": "https://example.com",
                    "name": ""
                },
                "childFrames": [
                    {
                        "frame": {
                            "id": "CHILD1",
                            "url": "https://example.com/iframe1",
                            "name": "frame-one"
                        },
                        "childFrames": [
                            {
                                "frame": {
                                    "id": "GRANDCHILD1",
                                    "url": "https://example.com/nested",
                                    "name": "nested-frame"
                                }
                            }
                        ]
                    },
                    {
                        "frame": {
                            "id": "CHILD2",
                            "url": "https://example.com/iframe2",
                            "name": ""
                        }
                    }
                ]
            }
        });

        let frames = parse_frame_tree(&tree);
        assert_eq!(frames.len(), 4);

        // Main -> no parent
        assert!(frames[0].parent_id.is_none());

        // Child1 -> parent is MAIN
        assert_eq!(frames[1].id, "CHILD1");
        assert_eq!(frames[1].parent_id, Some("MAIN".to_string()));

        // Grandchild1 -> parent is CHILD1
        assert_eq!(frames[2].id, "GRANDCHILD1");
        assert_eq!(frames[2].parent_id, Some("CHILD1".to_string()));
        assert_eq!(frames[2].name, "nested-frame");

        // Child2 -> parent is MAIN
        assert_eq!(frames[3].id, "CHILD2");
        assert_eq!(frames[3].parent_id, Some("MAIN".to_string()));
    }

    #[test]
    fn test_parse_frame_tree_correct_parent_chain() {
        // Verify the parent_id chain is correct: main -> child -> grandchild
        let tree = json!({
            "frameTree": {
                "frame": { "id": "A", "url": "https://a.com", "name": "" },
                "childFrames": [{
                    "frame": { "id": "B", "url": "https://b.com", "name": "b" },
                    "childFrames": [{
                        "frame": { "id": "C", "url": "https://c.com", "name": "c" }
                    }]
                }]
            }
        });

        let frames = parse_frame_tree(&tree);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].id, "A");
        assert!(frames[0].parent_id.is_none());
        assert_eq!(frames[1].id, "B");
        assert_eq!(frames[1].parent_id.as_deref(), Some("A"));
        assert_eq!(frames[2].id, "C");
        assert_eq!(frames[2].parent_id.as_deref(), Some("B"));
    }

    #[test]
    fn test_parse_frame_tree_empty_response() {
        let tree = json!({});
        let frames = parse_frame_tree(&tree);
        assert!(frames.is_empty());
    }
}
