const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  console.log("🌱 Seeding database...");

  await prisma.issue.createMany({
    data: [
      {
        title: "Grin Magazine Issue #1",
        pdfPath: "/pdfs/grin-magazine-volume-one-web.pdf"
      },
      // add more issues here
      /*
      {
        title: "Grinzine Issue #2",
        pdfPath: "/pdfs/issue2.pdf"
      },
      {
        title: "Grinzine Issue #3",
        pdfPath: "/pdfs/issue3.pdf"
      }
      */
    ],
  skipDuplicates: true // avoids duplicates if run multiple times
  });

  console.log("✅ Database seeded.");
}

main()
  .catch(e => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
