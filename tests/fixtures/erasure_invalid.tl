// Invalid @erasable usage: stored without purge path

@erasable
type UserProfile = private String

fn store_user(profile: UserProfile) {
    fs.write_file("users.json", profile)
}
