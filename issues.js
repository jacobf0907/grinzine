// Centralized issue definitions for both seeding and backend logic
// To add a new issue:
// 1. Add a new object to the ISSUES array below with the following fields:
//    - priceId: The Stripe Price ID for the issue
//    - title: The exact title to be used in the database
//    - pdfPath: The path to the PDF file for the issue
// Example:
// {
//   priceId: 'price_XXXXXXXXXXXX',
//   title: 'Grin Magazine Issue #2',
//   pdfPath: '/pdfs/grin-magazine-issue-2.pdf'
// },

const ISSUES = [
  {
    priceId: 'price_1RugTbJulbntxSe8oz8G1wql',
    title: 'Grin Magazine Issue #1',
    pdfPath: '/pdfs/grin-magazine-volume-one-web.pdf'
  },
  // Add more issues here as needed
];

module.exports = { ISSUES };
