from models import db_session, create_all, init, User

# Methods required:
#     - Get all public keys for an account, only for users who can edit
#     - Update encrypted aes key for an account, only for users who can edit
#     - Update public, encrypted private key pair, only for authenticated user

if __name__ == "__main__":
    init("sqlite:///test.sqlite")
    create_all()
    u = User(full_name="bob smith", username="mrbob", email="mrbob@bob.com",
        auth_hash="notahash")
    db_session.add(u)
    db_session.commit()
