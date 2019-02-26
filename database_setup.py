#!/usr/bin/env python3
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    name = Column(String(80))
    email = Column(String(80))
    img_url = Column(String(500))
    id = Column(Integer, primary_key=True)


class GarageSale(Base):
    __tablename__ = 'garagesale'

    id = Column(Integer, primary_key=True)
    name = Column(String(80))
    address = Column(String(500))

    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    child = relationship("Item", backref="parent", cascade="all,delete")

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'address': self.address
        }


class Item(Base):
    __tablename__ = 'products'

    id = Column(Integer, primary_key=True)
    name = Column(String(80))
    price = Column(String(12))
    description = Column(String(300))

    garage_sale_id = Column(Integer,
                            ForeignKey('garagesale.id', ondelete='CASCADE'))
    garagesale = relationship(GarageSale)

    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'price': self.price,
            'description': self.description,
            'garage_sale_id': self.garage_sale_id
        }


engine = create_engine('sqlite:///garagesale.db')
Base.metadata.create_all(engine)
