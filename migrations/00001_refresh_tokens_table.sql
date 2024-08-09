create table refresh_tokens (
    rt_hash char(60) primary key,
    rt_user_id uuid not null,
    rt_expires_at timestamp not null,
    rt_valid boolean not null default false
);