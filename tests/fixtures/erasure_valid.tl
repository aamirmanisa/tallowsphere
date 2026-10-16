// Valid @erasable usage: type with proper purge handling

@erasable
type UserProfile = private String

fn store_user(profile: UserProfile) {
    fs.write_file("users.json", profile)
    purge("user-123")
}

fn delete_user(profile: UserProfile) {
    db.delete("users", profile)
}
