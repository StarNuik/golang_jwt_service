create table users (
    user_id uuid primary key default gen_random_uuid(),
    user_name text not null,
    user_email text not null
);