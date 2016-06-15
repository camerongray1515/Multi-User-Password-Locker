from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker, relationship
from sqlalchemy import create_engine, Column, Integer, String, Text,\
    ForeignKey, Boolean

db_session = scoped_session(sessionmaker())
Base = declarative_base()
Base.query = db_session.query_property()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    full_name = Column(String)
    username = Column(String)
    email = Column(String)
    auth_hash = Column(String)
    encrypted_private_key = Column(Text)
    public_key = Column(Text)
    admin = Column(Boolean)

    account_data_items = relationship("AccountDataItem",
        cascade="all, delete, delete-orphan", backref="user")

    permissions = relationship("Permission",
        cascade="all, delete, delete-orphan", backref="user")

    def __repr__(self):
        return "<User id: {}, full_name: {}>".format(self.id, self.full_name)


class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    folder_id = Column(Integer, ForeignKey("folders.id"))

    account_data_items = relationship("AccountDataItem",
        cascade="all, delete, delete-orphan", backref="account")

    def __repr__(self):
        return "<Account id: {}>".format(self.id)


class AccountDataItem(Base):
    __tablename__ = "account_data"
    id = Column(Integer, primary_key=True)
    account_metadata = Column(Text)
    password = Column(Text)
    account_id = Column(Integer, ForeignKey("accounts.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    encrypted_aes_key = Column(Text)

    def __repr__(self):
        return "<AccountDataItem id: {}, account_id: {}>".format(self.id,
            self.account_id)


class Folder(Base):
    __tablename__ = "folders"
    id = Column(Integer, primary_key=True)
    name = Column(String)

    accounts = relationship("Account", cascade="all, delete, delete-orphan",
        backref="folder")

    permissions = relationship("Permission",
        cascade="all, delete, delete-orphan", backref="folder")

    def __repr__(self):
        return "<Folder id: {}, name: {}>".format(self.id, self.name)


class Permission(Base):
    __tablename__ = "permissions"
    id = Column(Integer, primary_key=True)
    read = Column(Boolean)
    write = Column(Boolean)
    user_id = Column(Integer, ForeignKey("users.id"))
    folder_id = Column(Integer, ForeignKey("folders.id"))

    def __repr__(self):
        return "<Permission id: {}, Read: {}, Write: {}>".format(self.id,
            self.read, self.write)

def create_all():
    Base.metadata.create_all()

def init(connection_string):
    engine = create_engine(connection_string)
    Base.metadata.bind = engine
