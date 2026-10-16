//! CDP resource blocking for bandwidth reduction (T3.22).
//!
//! Uses `Network.setBlockedURLs` to block images, fonts, analytics, and other
//! non-essential resources. Typical savings: 75-95% bandwidth, which translates
//! directly to proxy cost reduction.

use crate::browser::cdp::CdpClient;

/// Resource blocking profile — selects which URL patterns to block.
#[derive(Debug, Clone, PartialEq)]
pub enum BlockProfile {
    /// Block nothing (default).
    None,
    /// Block images, stylesheets, fonts, media — aggressive for fast scraping.
    Scraper,
    /// Block images, fonts, ads, trackers, analytics — balanced, keeps CSS.
    Balanced,
    /// Block everything (use only when you just need the HTML document).
    Minimal,
    /// Custom URL patterns.
    Custom(Vec<String>),
}

pub struct ResourceBlocker;

impl ResourceBlocker {
    /// Apply a block profile to an active CDP session.
    pub async fn apply(
        cdp: &CdpClient,
        session_id: &str,
        profile: BlockProfile,
    ) -> Result<(), String> {
        let patterns = Self::patterns_for_profile(&profile);

        // Ensure Network domain is enabled first (no-op if already on).
        let _ = cdp
            .send_command_with_session("Network.enable", None, session_id)
            .await
            .map_err(|e| format!("Network.enable failed: {e}"))?;

        let params = serde_json::json!({ "urls": patterns });
        cdp.send_command_with_session("Network.setBlockedURLs", Some(params), session_id)
            .await
            .map_err(|e| format!("Network.setBlockedURLs failed: {e}"))?;
        Ok(())
    }

    /// Clear all blocked URLs on a session.
    pub async fn clear(cdp: &CdpClient, session_id: &str) -> Result<(), String> {
        let empty: Vec<String> = Vec::new();
        let params = serde_json::json!({ "urls": empty });
        cdp.send_command_with_session("Network.setBlockedURLs", Some(params), session_id)
            .await
            .map_err(|e| format!("Network.setBlockedURLs failed: {e}"))?;
        Ok(())
    }

    /// Get the URL patterns for a given profile.
    pub fn patterns_for_profile(profile: &BlockProfile) -> Vec<String> {
        match profile {
            BlockProfile::None => vec![],
            BlockProfile::Scraper => vec![
                // Images
                "*.jpg".into(),
                "*.jpeg".into(),
                "*.png".into(),
                "*.gif".into(),
                "*.webp".into(),
                "*.svg".into(),
                "*.ico".into(),
                // Fonts
                "*.woff".into(),
                "*.woff2".into(),
                "*.ttf".into(),
                "*.otf".into(),
                "*.eot".into(),
                // Media
                "*.mp4".into(),
                "*.webm".into(),
                "*.mp3".into(),
                "*.ogg".into(),
                // Stylesheets
                "*.css".into(),
            ],
            BlockProfile::Balanced => {
                let mut patterns: Vec<String> = vec![
                    // Images
                    "*.jpg".into(),
                    "*.jpeg".into(),
                    "*.png".into(),
                    "*.gif".into(),
                    "*.webp".into(),
                    "*.svg".into(),
                    "*.ico".into(),
                    // Fonts
                    "*.woff".into(),
                    "*.woff2".into(),
                    "*.ttf".into(),
                    "*.otf".into(),
                    "*.eot".into(),
                    // Media
                    "*.mp4".into(),
                    "*.webm".into(),
                    "*.mp3".into(),
                    "*.ogg".into(),
                ];
                // Ad / tracker domains
                patterns.extend(
                    [
                        "*doubleclick.net*",
                        "*googlesyndication.com*",
                        "*google-analytics.com*",
                        "*googletagmanager.com*",
                        "*site-09.example/tr*",
                        "*scorecardresearch.com*",
                        "*hotjar.com*",
                        "*segment.io*",
                        "*mixpanel.com*",
                        "*optimizely.com*",
                        "*newrelic.com*",
                        "*adservice.google.com*",
                        "*amazon-adsystem.com*",
                        "*criteo.com*",
                        "*taboola.com*",
                        "*outbrain.com*",
                    ]
                    .iter()
                    .map(|s| s.to_string()),
                );
                patterns
            }
            BlockProfile::Minimal => vec!["*".into()],
            BlockProfile::Custom(patterns) => patterns.clone(),
        }
    }

    /// Estimate bandwidth savings as a percentage.
    pub fn estimated_savings_percent(profile: &BlockProfile) -> f64 {
        match profile {
            BlockProfile::None => 0.0,
            BlockProfile::Scraper => 85.0,
            BlockProfile::Balanced => 75.0,
            BlockProfile::Minimal => 95.0,
            BlockProfile::Custom(_) => 50.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_profile_has_no_patterns() {
        assert!(ResourceBlocker::patterns_for_profile(&BlockProfile::None).is_empty());
    }

    #[test]
    fn scraper_profile_includes_images_and_fonts() {
        let p = ResourceBlocker::patterns_for_profile(&BlockProfile::Scraper);
        assert!(p.iter().any(|s| s == "*.jpg"));
        assert!(p.iter().any(|s| s == "*.woff2"));
        assert!(p.iter().any(|s| s == "*.css"));
    }

    #[test]
    fn balanced_profile_includes_trackers() {
        let p = ResourceBlocker::patterns_for_profile(&BlockProfile::Balanced);
        assert!(p.iter().any(|s| s.contains("doubleclick")));
        assert!(p.iter().any(|s| s.contains("google-analytics")));
        // Balanced keeps CSS
        assert!(!p.iter().any(|s| s == "*.css"));
    }

    #[test]
    fn minimal_blocks_everything() {
        let p = ResourceBlocker::patterns_for_profile(&BlockProfile::Minimal);
        assert_eq!(p, vec!["*".to_string()]);
    }

    #[test]
    fn custom_profile_returns_provided_patterns() {
        let custom = vec!["*.xyz".to_string(), "*tracker*".to_string()];
        let p = ResourceBlocker::patterns_for_profile(&BlockProfile::Custom(custom.clone()));
        assert_eq!(p, custom);
    }

    #[test]
    fn savings_ordering_is_sensible() {
        assert!(
            ResourceBlocker::estimated_savings_percent(&BlockProfile::Minimal)
                > ResourceBlocker::estimated_savings_percent(&BlockProfile::Scraper)
        );
        assert!(
            ResourceBlocker::estimated_savings_percent(&BlockProfile::Scraper)
                > ResourceBlocker::estimated_savings_percent(&BlockProfile::Balanced)
        );
        assert_eq!(
            ResourceBlocker::estimated_savings_percent(&BlockProfile::None),
            0.0
        );
    }
}
