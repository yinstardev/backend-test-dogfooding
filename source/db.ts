import { Pool } from 'pg';

const pool = new Pool({
    connectionString: process.env.POSTGRES_URL + "?sslmode=require",
  })

pool.connect((err : any) => {
    if(err) throw err;
    console.log('Connected to DB Successfully');
})

async function query(text: string, params?: any[]) {
    try {
      const client = await pool.connect();
      const result = await client.query(text, params);
      client.release();
      return result;
    } catch (error) {
      throw error;
    }
  }
  
export { query };