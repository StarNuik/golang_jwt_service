create table Users (
    Id    uuid primary key default gen_random_uuid(),
    Name  text not null,
    Email text not null
);