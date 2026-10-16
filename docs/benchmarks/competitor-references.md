# TSK-1204 Competitor Benchmark References

Last verified: 2026-04-27 (America/Chicago)

## Bright Data
| URL | Metric/claim extracted | Benchmark use |
| --- | --- | --- |
| https://brightdata.com/pricing/web-unlocker | Web Unlocker list pricing: PAYG `$1.5 / 1K results`; committed tiers shown down to `$1 / 1K results`. | External cost baseline (`cost_per_1k_success_usd`) for managed unlocker APIs. |
| https://docs.brightdata.com/scraping-automation/web-unlocker/features | Usage is measured by CPM (cost per 1,000 successful requests); only successful requests count toward billing. | Billing denominator alignment for success-based comparisons. |
| https://docs.brightdata.com/scraping-automation/web-unlocker/configuration | Premium-domain mode exists and applies higher rates only to listed domains. | Separate benchmark cohorts: standard-domain vs premium-domain targets. |

## Zyte
| URL | Metric/claim extracted | Benchmark use |
| --- | --- | --- |
| https://www.zyte.com/pricing/ | PAYG ranges shown: HTTP body `~$0.13 to $1.27 / 1K`; browser-rendered `~$1.01 to $16.08 / 1K` by tier. | Price envelope for HTTP-first vs browser-rendered workloads. |
| https://docs.zyte.com/zyte-api/pricing.html | Standard plan rate limit shown as `3000 RPM`; Zyte states only successful responses are charged. | Throughput ceiling + billing semantics for normalized cost and success metrics. |
| https://docs.zyte.com/zyte-api/pricing.html | Additional priced features listed (actions, screenshots, network captures, extraction add-ons). | Include feature surcharges in apples-to-apples TCO runs. |

## Oxylabs
| URL | Metric/claim extracted | Benchmark use |
| --- | --- | --- |
| https://oxylabs.io/products/scraper-api/web/pricing | Web Scraper API pricing examples: non-JS categories (Amazon/Google/Other) and JS-rendered category; plan rate limits shown (for example `50 req/s` on Micro/Starter/Advanced). | Base cost and nominal submission-rate baseline. |
| https://developers.oxylabs.io/help-center/billing-and-payments/how-does-web-scraper-api-pricing-work | Success-based model: `2xx/4xx` counted as successful/billable; `5xx/6xx` not billed. | Normalize "billable success" definitions across vendors. |
| https://developers.oxylabs.io/scraping-solutions/web-scraper-api/usage-and-billing/rate-limits | Domain-level safeguard: if recent success rate drops below 40%, domain may be limited to `1 req/s` until recovery. | Add stress-test scenario for adaptive throttling under degraded success. |

## Firecrawl
| URL | Metric/claim extracted | Benchmark use |
| --- | --- | --- |
| https://www.firecrawl.dev/pricing | Plan concurrency examples shown: Free `2`, Hobby `5`, Standard `50`, Growth `100`, Scale `150` concurrent requests/browsers. | Concurrency baseline for plan-tier comparisons. |
| https://docs.firecrawl.dev/billing | Billing model states `Scrape = 1 credit/page` and plans are subscription + credit based. | Convert credits to effective per-page cost in monthly KPI reports. |
| https://docs.firecrawl.dev/features/batch-scrape | Batch scrape supports concurrent processing for URL lists in one job. | Use as multi-URL batch benchmark mode vs single-request loops. |

## ScrapingBee
| URL | Metric/claim extracted | Benchmark use |
| --- | --- | --- |
| https://www.scrapingbee.com/pricing/ | Plan concurrency examples: Freelance `10`, Startup `50`, Business `100`, Business+ `200`; credits/month shown per plan. | External throughput and budget tiers for competitive positioning. |
| https://help.scrapingbee.com/en/article/amount-of-credits-for-each-type-of-request-1h2ackp/ | Credit multipliers vary by request type (for example classic non-JS vs JS vs premium/stealth). | Weighted-request benchmark accounting (not just request count). |
| https://www.scrapingbee.com/documentation/ | `/usage` endpoint is available for credit/concurrency monitoring; endpoint itself has its own request limit. | Operational telemetry parity check for live benchmark runs. |
