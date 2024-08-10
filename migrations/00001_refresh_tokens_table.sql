create table RefreshTokens (
    Id          uuid      primary key,
    UserId      uuid      not null,
    Hash        text      not null,
    ExpiresAt   timestamp not null,
    Active      boolean   not null default false
);