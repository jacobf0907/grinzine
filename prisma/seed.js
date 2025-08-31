const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const { ISSUES } = require('../issues');

async function main() {
  console.log("🌱 Seeding database...");

  await prisma.issue.createMany({
    data: ISSUES.map(issue => ({
      title: issue.title,
      pdfPath: issue.pdfPath
    })),
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
