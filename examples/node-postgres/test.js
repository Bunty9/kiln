import assert from 'node:assert';
import pg from 'pg';

const { Client } = pg;

const client = new Client({
  connectionString: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/postgres',
});

await client.connect();

try {
  // Create table
  await client.query(`
    CREATE TABLE IF NOT EXISTS test_users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL
    )
  `);

  // Insert
  const insertResult = await client.query(
    'INSERT INTO test_users (name) VALUES ($1) RETURNING id, name',
    ['Alice']
  );
  const insertedId = insertResult.rows[0].id;
  const insertedName = insertResult.rows[0].name;

  // Select
  const selectResult = await client.query(
    'SELECT * FROM test_users WHERE id = $1',
    [insertedId]
  );

  // Assert
  assert.strictEqual(selectResult.rows.length, 1, 'Expected 1 row');
  assert.strictEqual(selectResult.rows[0].name, 'Alice', 'Expected name to be Alice');

  console.log('✓ All tests passed');
} finally {
  await client.end();
}
