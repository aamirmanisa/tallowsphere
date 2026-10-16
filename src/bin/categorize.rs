//! Tallow SIMD Smart Categorizer — Two-Pass System
//!
//! Pass 1: Detect product TYPE (food, household, health, pet, baby, alcohol)
//!         using brand names + non-food keywords
//! Pass 2: Assign department + subcategory within that type
//!
//! Prevents: soap categorized as "Dairy" because it says "milk",
//!           soda categorized as "Produce" because it says "grapefruit"
//!
//! Usage: categorize < products.jsonl > categorized.jsonl

use memchr::memmem;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};
use std::time::Instant;

#[derive(Deserialize)]
struct Product {
    id: Option<serde_json::Value>,
    name: Option<String>,
    brand: Option<String>,
    ingredients: Option<String>,
    department: Option<String>,
}

#[derive(Serialize)]
struct CategorizedProduct {
    id: serde_json::Value,
    department: String,
    category_path: String,
    dietary_tags: Vec<String>,
    allergens: Vec<String>,
}

// ============================================================
// PASS 1: Product type detection (non-food first)
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq)]
enum ProductType {
    Household,
    Health,
    Beauty,
    Pet,
    Baby,
    Alcohol,
    Food,
}

fn detect_type(name: &str, brand: &str) -> ProductType {
    let n = name.to_lowercase();
    let b = brand.to_lowercase();
    let combined = format!("{} {}", n, b);

    // Pet — check first (pet food brands are distinctive)
    let pet_brands = [
        "purina",
        "pedigree",
        "iams",
        "blue buffalo",
        "friskies",
        "fancy feast",
        "meow mix",
        "milk-bone",
        "beggin",
        "greenies",
        "temptations",
        "rachael ray nutrish",
        "wellness",
        "hill's",
        "royal canin",
        "nutro",
        "cesar ",
        "beneful",
        "kibbles",
        "alpo",
        "fresh step",
        "tidy cat",
        "arm & hammer cat",
        "world's best cat",
    ];
    for pb in &pet_brands {
        if combined.contains(pb) {
            return ProductType::Pet;
        }
    }
    if n.contains("dog food")
        || n.contains("cat food")
        || n.contains("cat litter")
        || n.contains("dog treat")
        || n.contains("cat treat")
        || n.contains("pet ")
        || n.contains("puppy")
        || n.contains("kitten")
        || n.contains("flea ")
        || n.contains("bird seed")
        || n.contains("fish food")
    {
        return ProductType::Pet;
    }

    // Household cleaning
    let household_brands = [
        "lysol",
        "clorox",
        "windex",
        "mr clean",
        "pine-sol",
        "swiffer",
        "pledge",
        "scrub",
        "febreze",
        "glade",
        "glad ",
        "hefty",
        "bounty",
        "charmin",
        "cottonelle",
        "scott ",
        "quilted",
        "dixie",
        "reynolds",
        "ziploc",
        "tide ",
        "gain ",
        "downy",
        "cascade",
        "finish ",
        "dawn ",
        "palmolive",
        "ajax ",
        "oxiclean",
        "resolve",
        "arm & hammer laundry",
        "snuggle",
        "all free",
    ];
    for hb in &household_brands {
        if combined.contains(hb) {
            return ProductType::Household;
        }
    }
    if n.contains("detergent")
        || n.contains("dish soap")
        || n.contains("cleaner")
        || n.contains("disinfect")
        || n.contains("paper towel")
        || n.contains("toilet paper")
        || n.contains("trash bag")
        || n.contains("garbage bag")
        || n.contains("dryer sheet")
        || n.contains("fabric softener")
        || n.contains("bleach")
        || n.contains("sponge")
        || n.contains("mop ")
        || n.contains("broom")
        || n.contains("air freshener")
        || n.contains("candle")
        || n.contains("aluminum foil")
        || n.contains("plastic wrap")
        || n.contains("parchment")
        || n.contains("light bulb")
        || n.contains("battery ")
        || n.contains("napkin")
        || n.contains("tissue box")
        || n.contains("stain remover")
    {
        return ProductType::Household;
    }

    // Health & Medicine
    let health_brands = [
        "tylenol",
        "advil",
        "aleve",
        "benadryl",
        "zyrtec",
        "claritin",
        "allegra",
        "nyquil",
        "dayquil",
        "mucinex",
        "robitussin",
        "tums",
        "pepto",
        "imodium",
        "dulcolax",
        "miralax",
        "metamucil",
        "band-aid",
        "neosporin",
        "preparation h",
    ];
    for hb in &health_brands {
        if combined.contains(hb) {
            return ProductType::Health;
        }
    }
    if n.contains("ibuprofen")
        || n.contains("acetaminophen")
        || n.contains("aspirin")
        || n.contains("medicine")
        || n.contains("supplement")
        || n.contains("vitamin ")
        || n.contains("multivitamin")
        || n.contains("probiotic")
        || n.contains("melatonin")
        || n.contains("fish oil")
        || n.contains("pain relief")
        || n.contains("allergy ")
        || n.contains("cold & flu")
        || n.contains("cough ")
        || n.contains("first aid")
        || n.contains("bandage")
        || n.contains("thermometer")
        || n.contains("antacid")
    {
        return ProductType::Health;
    }

    // Beauty & Personal Care
    let beauty_brands = [
        "dove",
        "nivea",
        "olay",
        "neutrogena",
        "l'oreal",
        "garnier",
        "pantene",
        "head & shoulders",
        "tresemme",
        "suave",
        "old spice",
        "secret ",
        "degree ",
        "axe ",
        "gillette",
        "venus",
        "schick",
        "harry's",
        "colgate",
        "crest",
        "oral-b",
        "listerine",
        "sensodyne",
        "aveeno",
        "cetaphil",
        "cerave",
        "vaseline",
        "jergens",
        "eucerin",
        "coppertone",
        "banana boat",
    ];
    for bb in &beauty_brands {
        if combined.contains(bb) {
            return ProductType::Beauty;
        }
    }
    if n.contains("shampoo")
        || n.contains("conditioner")
        || n.contains("body wash")
        || n.contains("bar soap")
        || n.contains("hand soap")
        || n.contains("deodorant")
        || n.contains("antiperspirant")
        || n.contains("toothpaste")
        || n.contains("toothbrush")
        || n.contains("mouthwash")
        || n.contains("dental floss")
        || n.contains("razor")
        || n.contains("shaving")
        || n.contains("lotion")
        || n.contains("moisturizer")
        || n.contains("sunscreen")
        || n.contains("lip balm")
        || n.contains("makeup")
        || n.contains("mascara")
        || n.contains("nail polish")
        || n.contains("hair dye")
        || n.contains("cotton swab")
        || n.contains("cotton ball")
    {
        return ProductType::Beauty;
    }

    // Baby (non-food)
    if n.contains("diaper")
        || n.contains("pull-up")
        || n.contains("baby wipe")
        || n.contains("baby lotion")
        || n.contains("baby shampoo")
        || n.contains("baby wash")
        || n.contains("diaper cream")
        || n.contains("pacifier")
        || n.contains("bottle ")
        || n.contains("sippy cup")
        || n.contains("nursing pad")
    {
        return ProductType::Baby;
    }

    // Alcohol
    if n.contains("vodka")
        || n.contains("whiskey")
        || n.contains("bourbon")
        || n.contains("tequila")
        || n.contains(" gin ")
        || n.contains("rum ")
        || n.contains("brandy")
        || n.contains("cognac")
        || n.contains("scotch")
        || n.contains("mezcal")
        || n.contains("wine ")
        || n.contains("cabernet")
        || n.contains("chardonnay")
        || n.contains("merlot")
        || n.contains("pinot")
        || n.contains("champagne")
        || n.contains("prosecco")
        || n.contains("moscato")
        || n.contains(" beer")
        || n.contains("craft beer")
        || n.contains(" ipa ")
        || n.contains("lager")
        || n.contains(" ale ")
        || n.contains("stout")
        || n.contains("hard seltzer")
        || n.contains("hard cider")
    {
        return ProductType::Alcohol;
    }

    ProductType::Food
}

// ============================================================
// PASS 2: Department + subcategory (only for detected type)
// ============================================================

fn categorize_food(name: &str) -> (&'static str, &'static str) {
    let n = name.to_lowercase();

    // Produce — Fruits
    if regex_match(
        &n,
        &[
            "banana",
            "apple ",
            "apples",
            "orange ",
            "oranges",
            "strawberr",
            "blueberr",
            "raspberr",
            "blackberr",
            "grape ",
            "grapes",
            "watermelon",
            "cantaloupe",
            "honeydew",
            "pineapple",
            "mango ",
            "mangoes",
            "peach ",
            "peaches",
            "pear ",
            "pears",
            "plum ",
            "nectarine",
            "kiwi",
            "cherry",
            "cherries",
            "pomegranate",
            "avocado",
            "lemon ",
            "lemons",
            "lime ",
            "limes",
            "grapefruit",
            "coconut",
            "fig ",
            "date ",
        ],
    ) {
        // But NOT if it's a flavored product (juice, yogurt, soda, candy, etc.)
        if !regex_match(
            &n,
            &[
                "juice",
                "yogurt",
                "soda",
                "candy",
                "gummy",
                "jam",
                "jelly",
                "preserves",
                "pie ",
                "cake",
                "muffin",
                "ice cream",
                "flavored",
                "flavor ",
                "scent",
                "fragrance",
                "extract",
                "syrup",
                "snack",
                "bar ",
                "drink",
                "tea ",
                "smoothie",
                "chips",
            ],
        ) {
            return ("Produce", "Fresh Fruits");
        }
    }

    // Produce — Vegetables
    if regex_match(
        &n,
        &[
            "tomato",
            "potato ",
            "potatoes",
            "sweet potato",
            "onion",
            "garlic ",
            "ginger ",
            "lettuce",
            "spinach",
            "kale ",
            "arugula",
            "broccoli",
            "cauliflower",
            "carrot",
            "celery",
            "cucumber",
            "zucchini",
            "squash",
            "eggplant",
            "bell pepper",
            "jalapeno",
            "mushroom",
            "corn ",
            "asparagus",
            "brussels",
            "cabbage",
            "radish",
            "beet ",
            "turnip",
        ],
    ) {
        if !regex_match(
            &n,
            &[
                "soup",
                "sauce",
                "chip",
                "snack",
                "frozen",
                "canned",
                "juice",
                "cream of",
                "powder",
                "seasoning",
                "flakes",
            ],
        ) {
            return ("Produce", "Fresh Vegetables");
        }
    }

    // Produce — Herbs
    if regex_match(
        &n,
        &[
            "fresh cilantro",
            "fresh basil",
            "fresh mint",
            "fresh parsley",
            "fresh rosemary",
            "fresh thyme",
            "fresh dill",
            "herb bundle",
        ],
    ) {
        return ("Produce", "Fresh Herbs");
    }

    // Dairy — check for actual dairy products, not things that mention milk/cheese
    if regex_match(
        &n,
        &[
            "whole milk",
            "2% milk",
            "1% milk",
            "skim milk",
            "fat free milk",
            "lowfat milk",
            "reduced fat milk",
            "chocolate milk",
            "strawberry milk",
            "buttermilk",
            "lactaid",
        ],
    ) {
        return ("Dairy & Eggs", "Milk");
    }
    if regex_match(
        &n,
        &[
            "oat milk",
            "almond milk",
            "soy milk",
            "coconut milk",
            "cashew milk",
            "rice milk",
            "flax milk",
            "plant based milk",
        ],
    ) {
        return ("Dairy & Eggs", "Plant-Based Milk");
    }
    if regex_match(
        &n,
        &[
            "cheddar cheese",
            "mozzarella cheese",
            "parmesan cheese",
            "swiss cheese",
            "provolone",
            "gouda",
            "brie ",
            "colby",
            "monterey jack",
            "pepper jack",
            "american cheese",
            "shredded cheese",
            "sliced cheese",
            "block cheese",
            "string cheese",
            "cream cheese",
            "cottage cheese",
            "ricotta",
            "feta ",
            "goat cheese",
            "blue cheese",
            "queso fresco",
        ],
    ) {
        return ("Dairy & Eggs", "Cheese");
    }
    if regex_match(&n, &["greek yogurt", "yogurt", "skyr", "kefir"]) {
        if !regex_match(&n, &["frozen yogurt", "yogurt covered", "yogurt pretzel"]) {
            return ("Dairy & Eggs", "Yogurt");
        }
    }
    if regex_match(
        &n,
        &[
            "butter ",
            "unsalted butter",
            "salted butter",
            "margarine",
            "ghee",
        ],
    ) {
        if !regex_match(
            &n,
            &[
                "peanut butter",
                "almond butter",
                "cookie butter",
                "body butter",
                "cocoa butter",
                "shea butter",
            ],
        ) {
            return ("Dairy & Eggs", "Butter & Spreads");
        }
    }
    if regex_match(
        &n,
        &[
            "dozen eggs",
            "large eggs",
            "cage free egg",
            "organic egg",
            "egg whites",
            "liquid egg",
            "brown eggs",
            "grade a egg",
        ],
    ) {
        return ("Dairy & Eggs", "Eggs");
    }
    if regex_match(
        &n,
        &[
            "sour cream",
            "heavy cream",
            "whipping cream",
            "half and half",
            "half & half",
            "coffee creamer",
        ],
    ) {
        return ("Dairy & Eggs", "Cream & Creamers");
    }

    // Meat
    if regex_match(
        &n,
        &[
            "chicken breast",
            "chicken thigh",
            "chicken wing",
            "chicken drumstick",
            "whole chicken",
            "rotisserie chicken",
            "chicken tender",
            "ground chicken",
        ],
    ) {
        return ("Meat & Seafood", "Chicken");
    }
    if regex_match(
        &n,
        &[
            "ground beef",
            "steak ",
            "ribeye",
            "sirloin",
            "filet mignon",
            "chuck roast",
            "brisket",
            "flank steak",
            "skirt steak",
            "ground round",
        ],
    ) {
        return ("Meat & Seafood", "Beef");
    }
    if regex_match(
        &n,
        &[
            "pork chop",
            "pork loin",
            "pork tenderloin",
            "pork shoulder",
            "pulled pork",
            "ground pork",
        ],
    ) {
        return ("Meat & Seafood", "Pork");
    }
    if regex_match(&n, &["bacon ", "turkey bacon", "canadian bacon"]) {
        return ("Meat & Seafood", "Bacon");
    }
    if regex_match(
        &n,
        &["sausage", "bratwurst", "kielbasa", "chorizo", "hot dog"],
    ) {
        return ("Meat & Seafood", "Sausage & Hot Dogs");
    }
    if regex_match(
        &n,
        &[
            "salmon ", "tuna ", "cod ", "tilapia", "catfish", "trout ", "mahi", "halibut",
            "snapper", "grouper",
        ],
    ) {
        if !regex_match(&n, &["canned", "can ", "pouch"]) {
            return ("Meat & Seafood", "Fresh Fish");
        }
    }
    if regex_match(
        &n,
        &["shrimp", "crab ", "lobster", "scallop", "clam ", "crawfish"],
    ) {
        return ("Meat & Seafood", "Shellfish");
    }

    // Bakery
    if regex_match(
        &n,
        &[
            "wheat bread",
            "white bread",
            "sourdough bread",
            "rye bread",
            "whole grain bread",
            "multigrain bread",
            "gluten free bread",
            "sandwich bread",
            "bread loaf",
        ],
    ) {
        return ("Bakery", "Bread");
    }
    if regex_match(
        &n,
        &[
            "flour tortilla",
            "corn tortilla",
            "wrap ",
            "pita bread",
            "naan ",
            "flatbread",
        ],
    ) {
        return ("Bakery", "Tortillas & Flatbreads");
    }
    if regex_match(
        &n,
        &[
            "bagel",
            "english muffin",
            "hamburger bun",
            "hot dog bun",
            "dinner roll",
            "croissant",
        ],
    ) {
        return ("Bakery", "Rolls & Buns");
    }

    // Pantry
    if regex_match(&n, &["peanut butter", "almond butter", "cashew butter"]) {
        return ("Pantry", "Nut Butters & Jelly");
    }
    if regex_match(
        &n,
        &[
            "pasta ",
            "spaghetti",
            "penne",
            "rigatoni",
            "fettuccine",
            "linguine",
            "rotini",
            "macaroni",
            "lasagna noodle",
        ],
    ) {
        return ("Pantry", "Pasta");
    }
    if regex_match(
        &n,
        &[
            "jasmine rice",
            "brown rice",
            "white rice",
            "basmati",
            "wild rice",
            "quinoa",
        ],
    ) {
        return ("Pantry", "Rice & Grains");
    }
    if regex_match(
        &n,
        &[
            "olive oil",
            "vegetable oil",
            "canola oil",
            "coconut oil",
            "avocado oil",
            "cooking spray",
        ],
    ) {
        return ("Pantry", "Cooking Oils");
    }
    if regex_match(
        &n,
        &[
            "black bean",
            "pinto bean",
            "kidney bean",
            "chickpea",
            "lentil",
            "refried bean",
        ],
    ) {
        return ("Pantry", "Beans & Legumes");
    }
    if regex_match(
        &n,
        &[
            "chicken broth",
            "beef broth",
            "vegetable broth",
            "bone broth",
        ],
    ) {
        return ("Pantry", "Broth & Stock");
    }
    if regex_match(
        &n,
        &[
            "tomato sauce",
            "marinara",
            "alfredo sauce",
            "pasta sauce",
            "pesto",
        ],
    ) {
        return ("Pantry", "Pasta Sauce");
    }
    if regex_match(
        &n,
        &[
            "flour ",
            "sugar ",
            "brown sugar",
            "baking powder",
            "baking soda",
            "vanilla extract",
            "cocoa powder",
            "chocolate chip",
            "cake mix",
        ],
    ) {
        return ("Pantry", "Baking");
    }
    if regex_match(
        &n,
        &[
            "cumin",
            "paprika",
            "cinnamon",
            "garlic powder",
            "onion powder",
            "taco seasoning",
            "italian seasoning",
            "chili powder",
            "black pepper",
        ],
    ) {
        return ("Pantry", "Spices & Seasonings");
    }
    if regex_match(&n, &["canned tuna", "canned salmon", "sardine"]) {
        return ("Pantry", "Canned Seafood");
    }
    if regex_match(&n, &["soup ", "chicken noodle", "tomato soup", "chili "]) {
        return ("Pantry", "Soup");
    }
    if regex_match(&n, &["honey ", "maple syrup", "agave"]) {
        return ("Pantry", "Honey & Syrups");
    }

    // Breakfast
    if regex_match(
        &n,
        &[
            "cereal",
            "cheerios",
            "frosted flakes",
            "corn flakes",
            "raisin bran",
            "froot loops",
        ],
    ) {
        return ("Breakfast", "Cereal");
    }
    if regex_match(
        &n,
        &["oatmeal", "instant oatmeal", "steel cut oat", "rolled oat"],
    ) {
        return ("Breakfast", "Oatmeal & Hot Cereal");
    }
    if regex_match(&n, &["granola "]) {
        return ("Breakfast", "Granola");
    }
    if regex_match(&n, &["pancake mix", "waffle mix"]) {
        return ("Breakfast", "Pancakes & Waffles");
    }

    // Snacks
    if regex_match(
        &n,
        &[
            "potato chip",
            "tortilla chip",
            "doritos",
            "lays ",
            "cheetos",
            "fritos",
            "pringles",
            "ruffles",
            "tostitos",
            "kettle chip",
        ],
    ) {
        return ("Snacks", "Chips");
    }
    if regex_match(
        &n,
        &[
            "pretzel",
            "cracker",
            "goldfish",
            "cheez-it",
            "wheat thin",
            "ritz ",
            "triscuit",
        ],
    ) {
        return ("Snacks", "Crackers & Pretzels");
    }
    if regex_match(&n, &["popcorn", "kettle corn"]) {
        return ("Snacks", "Popcorn");
    }
    if regex_match(
        &n,
        &[
            "trail mix",
            "mixed nuts",
            "almonds",
            "cashews",
            "walnuts",
            "pecans",
            "pistachios",
        ],
    ) {
        return ("Snacks", "Nuts & Trail Mix");
    }
    if regex_match(
        &n,
        &[
            "protein bar",
            "granola bar",
            "energy bar",
            "kind bar",
            "clif bar",
            "nature valley",
        ],
    ) {
        return ("Snacks", "Bars");
    }
    if regex_match(&n, &["beef jerky", "slim jim", "meat stick"]) {
        return ("Snacks", "Jerky");
    }
    if regex_match(&n, &["hummus", "guacamole", "salsa ", "queso ", "bean dip"]) {
        return ("Snacks", "Dips & Salsa");
    }

    // Frozen
    if regex_match(&n, &["frozen pizza", "digiorno", "totino", "red baron"]) {
        return ("Frozen", "Pizza");
    }
    if regex_match(
        &n,
        &[
            "ice cream",
            "blue bell",
            "ben & jerry",
            "haagen-dazs",
            "popsicle",
            "frozen yogurt",
            "sherbet",
            "sorbet",
        ],
    ) {
        return ("Frozen", "Ice Cream & Desserts");
    }
    if regex_match(
        &n,
        &[
            "frozen dinner",
            "lean cuisine",
            "healthy choice",
            "stouffer",
            "marie callender",
            "tv dinner",
            "pot pie",
        ],
    ) {
        return ("Frozen", "Frozen Meals");
    }
    if regex_match(
        &n,
        &["chicken nugget", "chicken strip", "corn dog", "fish stick"],
    ) {
        return ("Frozen", "Frozen Snacks");
    }
    if regex_match(&n, &["frozen fries", "tater tot", "hash brown"]) {
        return ("Frozen", "Frozen Potatoes");
    }
    if regex_match(
        &n,
        &[
            "hot pocket",
            "pizza roll",
            "bagel bite",
            "burrito",
            "taquito",
        ],
    ) {
        return ("Frozen", "Frozen Appetizers");
    }

    // Beverages
    if regex_match(
        &n,
        &[
            "coca-cola",
            "coca cola",
            "pepsi",
            "sprite",
            "dr pepper",
            "dr. pepper",
            "mountain dew",
            "diet coke",
            "coke zero",
            "ginger ale",
            "root beer",
            "7up",
            "fanta",
            "sierra mist",
        ],
    ) {
        return ("Beverages", "Soda");
    }
    if regex_match(
        &n,
        &[
            "sparkling water",
            "seltzer",
            "topo chico",
            "la croix",
            "perrier",
            "mineral water",
        ],
    ) {
        return ("Beverages", "Sparkling Water");
    }
    if regex_match(
        &n,
        &[
            "orange juice",
            "apple juice",
            "grape juice",
            "cranberry juice",
            "lemonade",
            "fruit punch",
        ],
    ) {
        return ("Beverages", "Juice");
    }
    if regex_match(
        &n,
        &[
            "ground coffee",
            "coffee bean",
            "k-cup",
            "keurig",
            "cold brew",
            "espresso",
            "instant coffee",
        ],
    ) {
        return ("Beverages", "Coffee");
    }
    if regex_match(
        &n,
        &[
            "green tea",
            "black tea",
            "herbal tea",
            "iced tea",
            "chai tea",
        ],
    ) {
        return ("Beverages", "Tea");
    }
    if regex_match(
        &n,
        &[
            "energy drink",
            "red bull",
            "monster energy",
            "celsius",
            "bang energy",
            "reign",
        ],
    ) {
        return ("Beverages", "Energy Drinks");
    }
    if regex_match(&n, &["gatorade", "powerade", "body armor", "sports drink"]) {
        return ("Beverages", "Sports Drinks");
    }
    if regex_match(&n, &["bottled water", "spring water", "purified water"]) {
        return ("Beverages", "Water");
    }

    // Condiments
    if regex_match(&n, &["ketchup", "mustard ", "dijon"]) {
        return ("Condiments", "Ketchup & Mustard");
    }
    if regex_match(&n, &["mayonnaise", "mayo "]) {
        return ("Condiments", "Mayonnaise");
    }
    if regex_match(&n, &["hot sauce", "sriracha", "tabasco", "cholula"]) {
        return ("Condiments", "Hot Sauce");
    }
    if regex_match(&n, &["bbq sauce", "barbecue sauce"]) {
        return ("Condiments", "BBQ Sauce");
    }
    if regex_match(
        &n,
        &[
            "ranch dressing",
            "salad dressing",
            "italian dressing",
            "caesar dressing",
            "vinaigrette",
        ],
    ) {
        return ("Condiments", "Salad Dressing");
    }
    if regex_match(&n, &["soy sauce", "teriyaki", "hoisin", "oyster sauce"]) {
        return ("Condiments", "Asian Sauces");
    }

    // Baby food
    if regex_match(&n, &["baby food", "infant food", "gerber ", "beech-nut"]) {
        return ("Baby", "Baby Food");
    }
    if regex_match(
        &n,
        &["baby formula", "infant formula", "enfamil", "similac"],
    ) {
        return ("Baby", "Formula");
    }

    ("General Grocery", "General Grocery")
}

fn categorize_nonfood(product_type: ProductType, name: &str) -> (&'static str, &'static str) {
    let n = name.to_lowercase();
    match product_type {
        ProductType::Household => {
            if n.contains("paper towel")
                || n.contains("toilet paper")
                || n.contains("tissue")
                || n.contains("napkin")
            {
                ("Household", "Paper Products")
            } else if n.contains("detergent")
                || n.contains("fabric softener")
                || n.contains("dryer sheet")
                || n.contains("bleach")
            {
                ("Household", "Laundry")
            } else if n.contains("dish soap") || n.contains("dishwasher") {
                ("Household", "Dish Care")
            } else if n.contains("trash bag") || n.contains("garbage bag") {
                ("Household", "Trash Bags")
            } else if n.contains("foil")
                || n.contains("plastic wrap")
                || n.contains("zip")
                || n.contains("parchment")
            {
                ("Household", "Food Storage")
            } else if n.contains("cleaner") || n.contains("disinfect") || n.contains("wipes") {
                ("Household", "Cleaning")
            } else if n.contains("air freshener") || n.contains("candle") {
                ("Household", "Air Fresheners")
            } else {
                ("Household", "Household Essentials")
            }
        }
        ProductType::Health => {
            if n.contains("vitamin")
                || n.contains("supplement")
                || n.contains("probiotic")
                || n.contains("fish oil")
            {
                ("Health", "Vitamins & Supplements")
            } else if n.contains("pain")
                || n.contains("ibuprofen")
                || n.contains("acetaminophen")
                || n.contains("aspirin")
            {
                ("Health", "Pain Relief")
            } else if n.contains("allergy") || n.contains("zyrtec") || n.contains("claritin") {
                ("Health", "Allergy")
            } else if n.contains("cold") || n.contains("cough") || n.contains("flu") {
                ("Health", "Cold & Flu")
            } else if n.contains("bandage") || n.contains("band-aid") || n.contains("first aid") {
                ("Health", "First Aid")
            } else {
                ("Health", "Health Care")
            }
        }
        ProductType::Beauty => {
            if n.contains("shampoo") || n.contains("conditioner") || n.contains("hair ") {
                ("Health & Beauty", "Hair Care")
            } else if n.contains("body wash") || n.contains("bar soap") || n.contains("hand soap") {
                ("Health & Beauty", "Body Care")
            } else if n.contains("deodorant") || n.contains("antiperspirant") {
                ("Health & Beauty", "Deodorant")
            } else if n.contains("toothpaste")
                || n.contains("toothbrush")
                || n.contains("mouthwash")
                || n.contains("floss")
            {
                ("Health & Beauty", "Oral Care")
            } else if n.contains("lotion") || n.contains("moisturizer") || n.contains("sunscreen") {
                ("Health & Beauty", "Skin Care")
            } else if n.contains("razor") || n.contains("shaving") {
                ("Health & Beauty", "Shaving")
            } else {
                ("Health & Beauty", "Personal Care")
            }
        }
        ProductType::Pet => {
            if n.contains("dog food") || n.contains("puppy") {
                ("Pet", "Dog Food")
            } else if n.contains("cat food")
                || n.contains("kitten")
                || n.contains("fancy feast")
                || n.contains("friskies")
                || n.contains("meow mix")
            {
                ("Pet", "Cat Food")
            } else if n.contains("cat litter") || n.contains("kitty litter") {
                ("Pet", "Cat Litter")
            } else if n.contains("dog treat") || n.contains("milk-bone") || n.contains("beggin") {
                ("Pet", "Dog Treats")
            } else if n.contains("cat treat") || n.contains("temptation") {
                ("Pet", "Cat Treats")
            } else {
                ("Pet", "Pet Supplies")
            }
        }
        ProductType::Baby => {
            if n.contains("diaper") || n.contains("pull-up") {
                ("Baby", "Diapers")
            } else if n.contains("wipe") {
                ("Baby", "Wipes")
            } else if n.contains("formula") {
                ("Baby", "Formula")
            } else {
                ("Baby", "Baby Care")
            }
        }
        ProductType::Alcohol => {
            if n.contains("beer")
                || n.contains("ipa")
                || n.contains("lager")
                || n.contains("ale ")
                || n.contains("stout")
            {
                ("Beer, Wine & Spirits", "Beer")
            } else if n.contains("wine")
                || n.contains("cabernet")
                || n.contains("chardonnay")
                || n.contains("merlot")
                || n.contains("pinot")
                || n.contains("champagne")
                || n.contains("prosecco")
            {
                ("Beer, Wine & Spirits", "Wine")
            } else if n.contains("hard seltzer") || n.contains("hard cider") {
                ("Beer, Wine & Spirits", "Hard Seltzer")
            } else {
                ("Beer, Wine & Spirits", "Spirits")
            }
        }
        ProductType::Food => ("General Grocery", "General Grocery"),
    }
}

/// Check if name contains any of the patterns
fn regex_match(name: &str, patterns: &[&str]) -> bool {
    for p in patterns {
        if name.contains(p) {
            return true;
        }
    }
    false
}

fn dietary_tags(name: &str) -> Vec<String> {
    let n = name.to_lowercase();
    let mut tags = Vec::new();
    if n.contains("organic") {
        tags.push("organic".into());
    }
    if n.contains("gluten free") || n.contains("gluten-free") {
        tags.push("gluten-free".into());
    }
    if n.contains("vegan") {
        tags.push("vegan".into());
    }
    if n.contains("sugar free") || n.contains("sugar-free") || n.contains("zero sugar") {
        tags.push("sugar-free".into());
    }
    if n.contains("keto") {
        tags.push("keto".into());
    }
    if n.contains("low sodium") {
        tags.push("low-sodium".into());
    }
    if n.contains("non-gmo") || n.contains("non gmo") {
        tags.push("non-gmo".into());
    }
    if n.contains("dairy free") || n.contains("dairy-free") || n.contains("lactose free") {
        tags.push("dairy-free".into());
    }
    if n.contains("plant based") || n.contains("plant-based") {
        tags.push("plant-based".into());
    }
    if n.contains("whole grain") || n.contains("whole wheat") {
        tags.push("whole-grain".into());
    }
    if n.contains("kosher") {
        tags.push("kosher".into());
    }
    if n.contains("halal") {
        tags.push("halal".into());
    }
    tags
}

fn main() {
    let start = Instant::now();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    let lines: Vec<String> = stdin.lock().lines().filter_map(|l| l.ok()).collect();
    eprintln!(
        "Read {} products, categorizing with SIMD two-pass...",
        lines.len()
    );

    let results: Vec<Option<CategorizedProduct>> = lines
        .par_iter()
        .map(|line| {
            let p: Product = serde_json::from_str(line).ok()?;
            let id = p.id?;
            let name = p.name.unwrap_or_default();
            let brand = p.brand.unwrap_or_default();

            // Pass 1: Detect type
            let ptype = detect_type(&name, &brand);

            // Pass 2: Assign department + subcategory
            let (dept, sub) = if ptype == ProductType::Food {
                categorize_food(&name)
            } else {
                categorize_nonfood(ptype, &name)
            };

            let category_path = if dept == sub {
                dept.to_string()
            } else {
                format!("{} > {}", dept, sub)
            };

            let tags = dietary_tags(&name);

            Some(CategorizedProduct {
                id,
                department: dept.to_string(),
                category_path,
                dietary_tags: tags,
                allergens: vec![],
            })
        })
        .collect();

    // Stats
    let mut dept_counts = std::collections::HashMap::new();
    let mut sub_counts = std::collections::HashMap::new();
    let mut count = 0;

    for result in results.into_iter().flatten() {
        *dept_counts.entry(result.department.clone()).or_insert(0) += 1;
        *sub_counts.entry(result.category_path.clone()).or_insert(0) += 1;
        let json = serde_json::to_string(&result).unwrap();
        writeln!(out, "{}", json).unwrap();
        count += 1;
    }

    let elapsed = start.elapsed();
    eprintln!("\n=== DEPARTMENTS ({}) ===", dept_counts.len());
    let mut depts: Vec<_> = dept_counts.iter().collect();
    depts.sort_by(|a, b| b.1.cmp(a.1));
    for (d, c) in &depts {
        eprintln!("  {}: {}", d, c);
    }

    eprintln!("\n=== TOP SUBCATEGORIES ===");
    let mut subs: Vec<_> = sub_counts.iter().collect();
    subs.sort_by(|a, b| b.1.cmp(a.1));
    for (s, c) in subs.iter().take(30) {
        eprintln!("  {}: {}", s, c);
    }

    eprintln!(
        "\nCategorized {} products in {:.1}ms ({:.0}/sec) | {} depts | {} subcats",
        count,
        elapsed.as_secs_f64() * 1000.0,
        count as f64 / elapsed.as_secs_f64(),
        dept_counts.len(),
        sub_counts.len()
    );
}
