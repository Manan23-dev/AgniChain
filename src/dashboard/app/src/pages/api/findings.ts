import type { NextApiRequest, NextApiResponse } from "next";
import { Firestore } from "@google-cloud/firestore";

const firestore = new Firestore({
  projectId: process.env.GCP_PROJECT_ID,
});

interface Finding {
  id: string;
  pr_number: string;
  commit_sha: string;
  type: string;
  created_at?: any;
  scan_timestamp?: any;
  risk_level?: string;
  risk_score?: number;
  cve_count?: number;
  findings_count?: number;
  components_count?: number;
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const collection = firestore.collection(
      process.env.FIRESTORE_COLLECTION || "agni_findings"
    );

    // Fetch latest 50 records
    // Note: Some documents may have 'created_at', others 'scan_timestamp'
    // We'll sort in memory after fetching
    const snapshot = await collection.limit(50).get();

    const findings: Finding[] = [];
    const prMap = new Map<string, any>();

    // Convert to array and sort by timestamp
    const docs = snapshot.docs.map((doc) => ({
      id: doc.id,
      data: doc.data(),
    }));

    // Sort by created_at or scan_timestamp (descending)
    docs.sort((a, b) => {
      const aTime = a.data.created_at?.toDate() || a.data.scan_timestamp?.toDate() || new Date(0);
      const bTime = b.data.created_at?.toDate() || b.data.scan_timestamp?.toDate() || new Date(0);
      return bTime.getTime() - aTime.getTime();
    });

    docs.forEach(({ id: docId, data }) => {
      // Group by PR number
      const prNumber = data.pr_number || "unknown";
      if (!prMap.has(prNumber)) {
        prMap.set(prNumber, {
          pr_number: prNumber,
          commit_sha: data.commit_sha || "",
          scan: null,
          correlation: null,
          triage: null,
          created_at: data.created_at?.toDate() || data.scan_timestamp?.toDate() || new Date(),
        });
      }

      const prData = prMap.get(prNumber);
      const docType = data.type || "unknown";

      if (docType === "scan") {
        prData.scan = {
          ...data,
          id: docId,
          components_count: data.sbom_components?.length || 0,
          findings_count: data.findings?.length || 0,
        };
      } else if (docType === "correlation") {
        prData.correlation = {
          ...data,
          id: docId,
        };
      } else if (docType === "triage") {
        prData.triage = {
          ...data,
          id: docId,
          risk_level: data.risk_level,
          risk_score: data.risk_score,
          cve_count: data.cve_count,
          findings_count: data.findings_count,
        };
      }
    });

    // Convert map to array and sort by created_at
    const results = Array.from(prMap.values()).sort(
      (a, b) => b.created_at.getTime() - a.created_at.getTime()
    );

    return res.status(200).json({ findings: results });
  } catch (error: any) {
    console.error("Error fetching findings:", error);
    return res.status(500).json({ error: error.message });
  }
}

