import pg from "pg";

const { DATABASE_URL, PGSSL } = process.env;
if (!DATABASE_URL) {
  console.error("Falta a variável DATABASE_URL. No Railway, adicione um banco Postgres ao projeto.");
  process.exit(1);
}

export const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: PGSSL === "true" ? { rejectUnauthorized: false } : false,
});
export const q = (text, params) => pool.query(text, params);

export async function initDb() {
  await q(`
    create table if not exists events (
      id bigserial primary key,
      at timestamptz not null default now(),
      type text not null,
      ig_id text,
      payload jsonb
    );
    create index if not exists events_type_id on events (type, id desc);
    create table if not exists contacts (
      id bigserial primary key,
      ig_id text not null,
      scoped_id text not null,
      username text,
      tags text[] not null default '{}',
      comments int not null default 0,
      first_seen timestamptz not null default now(),
      last_seen timestamptz not null default now(),
      unique (ig_id, scoped_id)
    );
    create table if not exists handled_comments (
      comment_id text primary key,
      at timestamptz not null default now()
    );
  `);
}
