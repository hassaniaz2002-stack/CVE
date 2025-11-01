const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');

const app = express();
const port = process.env.PORT || 3001;

// PostgreSQL connection via environment variables
// DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
const pool = new Pool({
  host: process.env.DB_HOST || 'postgres',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || '12class34',
  database: process.env.DB_NAME || 'ooredoo_crm_en',
});

app.use(cors());

// Serve static frontend
const frontendPath = path.join(__dirname, '..', 'frontend');
app.use(express.static(frontendPath));

app.get('/api/cves', async (req, res) => {
  try {
    // First, let's check what columns exist in the table
    const columnCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'cve' AND table_schema = 'public'
      ORDER BY ordinal_position
    `);
    
    console.log('Available columns:', columnCheck.rows.map(r => r.column_name));
    
    // Select all columns - PostgreSQL returns lowercase unless quoted
    const result = await pool.query('SELECT * FROM cve');
    
    // Normalize the data to ensure consistent field names
    const normalizedRows = result.rows.map(row => {
      const normalized = { ...row }; // Start with all original fields
      // Map all possible column name variations to ensure frontend can find them
      Object.keys(row).forEach(key => {
        const lowerKey = key.toLowerCase();
        const value = row[key];
        
        // Map CVE variations
        if (lowerKey === 'cve' || lowerKey === 'cve_id') {
          normalized.cve = value;
          normalized.CVE = value;
        }
        
        // Map vendor
        if (lowerKey === 'vendor') {
          normalized.vendor = value;
        }
        
        // Map products
        if (lowerKey === 'products' || lowerKey === 'product') {
          normalized.products = value;
          normalized.product = value;
        }
        
        // Map description
        if (lowerKey === 'description') {
          normalized.description = value;
        }
        
        // Map base_score variations
        if (lowerKey === 'base_score' || lowerKey === 'cvss_score') {
          normalized.base_score = value;
          normalized.Base_Score = value;
          normalized.cvss_score = value;
        }
        
        // Map base_severity variations
        if (lowerKey === 'base_severity' || lowerKey === 'severity' || lowerKey === 'cvss_severity') {
          normalized.base_severity = value;
          normalized.Base_Severity = value;
          normalized.severity = value;
        }
        
        // Map published_date variations
        if (lowerKey === 'published_date' || lowerKey === 'published' || lowerKey === 'date' || lowerKey === 'created_at') {
          normalized.published_date = value;
          normalized.Published_Date = value;
          normalized.published = value;
        }
      });
      return normalized;
    });
    
    // Log first row to debug
    if (normalizedRows.length > 0) {
      console.log('Sample normalized row keys:', Object.keys(normalizedRows[0]));
      console.log('Sample base_score:', normalizedRows[0].base_score);
      console.log('Sample base_severity:', normalizedRows[0].base_severity);
    }
    
    res.json(normalizedRows);
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).send('Server Error');
  }
});

// Serve index.html at root
app.get('/', (req, res) => {
  res.sendFile(path.join(frontendPath, 'index.html'));
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
