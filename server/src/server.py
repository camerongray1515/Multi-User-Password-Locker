from models import db_session, create_all, init, User

# Methods required:
#   - Get all public keys for an account, only for users who can edit
#   - Update encrypted aes key for an account, only for users who can edit
#       or own account
#   - Update public, encrypted private key pair and auth key (hashed server
#       side), only for authenticated user
#   - Get metadata for all accounts in a folder, only for authenticated user
#   - Get password for an account, only for authenticated user
#   - Get encrypted private key for a user, only for authenticated user
#   - Get all folders, only for authenticated user
#
# Also need an endpoint where multiple updates can be sent in a single request
# to be carried out.  Some operations such as changing a user password will
# require many different fields to be updated, this must be done in a single
# request so that if the client disconnects the database cannot be left in a
# half-updated state.
#

if __name__ == "__main__":
    init("sqlite:///test.sqlite")
    create_all()
    u = User(full_name="bob smith", username="mrbob", email="mrbob@bob.com",
        auth_hash="notahash")
    db_session.add(u)
    db_session.commit()
