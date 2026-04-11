// Centralized issue definitions for both seeding and backend logic
// NOTE: Issue data is now also available in docs/issues.json for frontend use
// To add a new issue:
// 1. Add a new object to the ISSUES array below with the following fields:
//    - priceIdLive: The Stripe Price ID for live mode
//    - priceIdTest: The Stripe Price ID for test mode
//    - title: The exact title to be used in the database
//    - pdfPath: The path to the PDF file for the issue
// 2. Update docs/issues.json with the same information plus:
//    - id: Sequential issue number
//    - coverImage: Path to the cover image
// Example:
// {
//   priceIdLive: 'price_XXXXXXXXXXXX',
//   priceIdTest: 'price_XXXXXXXXXXXX',
//   title: 'Grin Magazine Issue #4',
//   pdfPath: '/pdfs/grin-magazine-issue-4.pdf'
// },

const ISSUES = [
  {
    priceIdLive: 'price_1S2bHIF8I4vGxQh7byJ1ky6x',
    priceIdTest: 'price_1RugTbJulbntxSe8oz8G1wql',
    title: 'Grin Magazine Issue #1',
    pdfPath: '/pdfs/grin-magazine-volume-one-web.pdf'
  },
  {
    priceIdLive: 'price_1SZ1QDF8I4vGxQh7Ivk0BhUv',
    priceIdTest: 'price_1SZIszJulbntxSe8RJNe7KFq',
    title: 'Grin Magazine Issue #2',
    pdfPath: '/data/pdfs/grinzine_issue_2_web.pdf'  // Must match mount point
  },
  {
    priceIdLive: 'price_1TL3hSF8I4vGxQh7KjJgYPTY',
    priceIdTest: 'price_1TL4yOJulbntxSe8DRB4Hp8D',
    title: 'Grin Magazine Issue #3',
    pdfPath: '/pdfs/grinzine-issue-3.pdf'  // URL path (not physical path)
  },
];

module.exports = { ISSUES };
