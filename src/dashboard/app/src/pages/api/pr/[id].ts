import type { NextApiRequest, NextApiResponse } from "next";
import { Firestore } from "@google-cloud/firestore";

const firestore = new Firestore({
  projectId: process.env.GCP_PROJECT_ID,
});

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { id } = req.query;
  const prNumber = id as string;

  try {
    const collection = firestore.collection(
      process.env.FIRESTORE_COLLECTION || "agni_findings"
    );

    // Find all documents for this PR
    const scanQuery = collection
      .where("pr_number", "==", prNumber)
      .where("type", "==", "scan")
      .limit(1);
    const correlationQuery = collection
      .where("pr_number", "==", prNumber)
      .where("type", "==", "correlation")
      .limit(1);
    const triageQuery = collection
      .where("pr_number", "==", prNumber)
      .where("type", "==", "triage")
      .limit(1);

    const [scanSnapshot, correlationSnapshot, triageSnapshot] = await Promise.all([
      scanQuery.get(),
      correlationQuery.get(),
      triageQuery.get(),
    ]);

    let scanData = null;
    let correlationData = null;
    let triageData = null;

    if (!scanSnapshot.empty) {
      const doc = scanSnapshot.docs[0];
      scanData = { id: doc.id, ...doc.data() };
    }

    if (!correlationSnapshot.empty) {
      const doc = correlationSnapshot.docs[0];
      correlationData = { id: doc.id, ...doc.data() };
    }

    if (!triageSnapshot.empty) {
      const doc = triageSnapshot.docs[0];
      triageData = { id: doc.id, ...doc.data() };
    }

    if (!scanData && !correlationData && !triageData) {
      return res.status(404).json({ error: "PR not found" });
    }

    // Flatten CVEs from correlation data
    const cves: any[] = [];
    if (correlationData?.components) {
      for (const comp of correlationData.components) {
        for (const vuln of comp.vulnerabilities || []) {
          cves.push({
            id: vuln.id,
            summary: vuln.summary,
            severity: vuln.severity,
            references: vuln.references || [],
            package: comp.name,
            package_version: comp.version,
            ecosystem: comp.ecosystem,
          });
        }
      }
    }

    // Normalize SBOM components
    const sbomComponents = scanData?.sbom_components || [];

    return res.status(200).json({
      pr_number: prNumber,
      commit_sha: scanData?.commit_sha || correlationData?.commit_sha || "",
      scan: scanData,
      correlation: correlationData,
      triage: triageData,
      sbom_components: sbomComponents,
      cves: cves,
    });
  } catch (error: any) {
    console.error("Error fetching PR data:", error);
    return res.status(500).json({ error: error.message });
  }
}

