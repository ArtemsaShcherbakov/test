const express = require('express');
const { Client } = require('pg');

const app = express();
const client = new Client({  });

app.get('/user', async (req, res) => {
    const userId = req.query.id; // например, "1 OR 1=1; --"
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    const result = await client.query(query);
    res.json(result.rows);
});
