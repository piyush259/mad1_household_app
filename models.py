from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class Users(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'admin', 'customer', or 'professional'
    address = db.Column(db.String(255))
    state = db.Column(db.String(255))
    pincode = db.Column(db.String(10))
    phone_number = db.Column(db.String(15), nullable=False)
    is_blocked = db.Column(db.Boolean, default=False)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    # Relationships
    professional_profile = db.relationship('ServiceProfessional', back_populates='user', uselist=False)
    customer_profile = db.relationship('Customer', back_populates='user', uselist=False)

    def __repr__(self):
        return f"<User {self.email}>"


class Customer(db.Model):
    __tablename__ = 'customers'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)

    service_requests = db.relationship(
        'ServiceRequest',
        back_populates='customer',
        cascade="all, delete-orphan"
    )
    user = db.relationship('Users', back_populates='customer_profile')
    def __repr__(self):
        return f"<Customer {self.user.email if self.user else 'No User'}>"


class ServiceProfessional(db.Model):
    __tablename__ = 'professionals'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    service_type = db.Column(db.String(255), nullable=False)
    experience = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=True)
    rating = db.Column(db.Float, default=0.0)
    total_ratings = db.Column(db.Integer, default=0)
    file_path = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), default='pending') # 'pending', 'approved', 'rejected'

    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=True)

    # Relationships
    category = db.relationship('Category', back_populates='professionals')
    services = db.relationship('Service', back_populates='professional', cascade='all, delete-orphan')
    service_requests = db.relationship('ServiceRequest', back_populates='professional', cascade='all, delete-orphan')
    user = db.relationship('Users', back_populates='professional_profile')
    reviews = db.relationship('Review', back_populates='professional', cascade="all, delete")


    def __repr__(self):
        return f"<ServiceProfessional {self.user_id}>"



class Category(db.Model):
    __tablename__ = 'categories'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    base_price = db.Column(db.Float, nullable=False)

    # Relationships
    services = db.relationship('Service', back_populates='category')
    professionals = db.relationship('ServiceProfessional', back_populates='category')

    def __repr__(self):
        return f"<Category {self.name}>"



class Service(db.Model):
    __tablename__ = 'services'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Float, nullable=False)
    time_required = db.Column(db.Integer, nullable=False)  # Time in minutes
    description = db.Column(db.Text)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('professionals.id', ondelete='CASCADE'), nullable=False)

    category = db.relationship('Category', back_populates='services')
    professional = db.relationship('ServiceProfessional', back_populates='services')
    service_requests = db.relationship('ServiceRequest', back_populates='service', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Service {self.name}>"
    

class ServiceRequest(db.Model):
    __tablename__ = 'service_requests'

    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id', ondelete='CASCADE'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id', ondelete='SET NULL'), nullable=True)  # Allow NULL
    professional_id = db.Column(db.Integer, db.ForeignKey('professionals.id'), nullable=True)
    date_of_request = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    service_status = db.Column(db.String(50), db.ForeignKey('service_history.service_status'), nullable=False, default='requested')
    date_of_completion = db.Column(db.DateTime, db.ForeignKey('service_history.date_of_completion'))

    service = db.relationship('Service', back_populates='service_requests')
    customer = db.relationship('Customer', back_populates='service_requests')
    professional = db.relationship('ServiceProfessional', back_populates='service_requests')
    histories = db.relationship('ServiceHistory', back_populates='service_request', foreign_keys='ServiceHistory.service_request_id')
    reviews = db.relationship('Review', back_populates='service_request')

    def __repr__(self):
        return f"<ServiceRequest {self.id}>"





class ServiceHistory(db.Model):
    __tablename__ = 'service_history'

    id = db.Column(db.Integer, primary_key=True)
    service_request_id = db.Column(db.Integer, db.ForeignKey('service_requests.id'), nullable=True)
    professional_id = db.Column(db.Integer, db.ForeignKey('professionals.id'), nullable=True)
    date_of_request = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    service_status = db.Column(db.String(50), nullable=False, default='requested')  # 'requested', 'accepted', 'completed', 'cancelled'
    date_of_completion = db.Column(db.DateTime)
    remarks = db.Column(db.Text)
    professional_name=db.Column(db.String(255), nullable=False)
    service_name=db.Column(db.String(255), nullable=False)
    customer_name=db.Column(db.String(255), nullable=False)

    service_request = db.relationship('ServiceRequest', back_populates='histories', foreign_keys=[service_request_id])

    def __repr__(self):
        return f"<ServiceHistory {self.id}>"


class Review(db.Model):
    __tablename__ = 'reviews'

    id = db.Column(db.Integer, primary_key=True)
    service_request_id = db.Column(db.Integer, db.ForeignKey('service_requests.id'), nullable=True)  # Make nullable=True
    rating = db.Column(db.Float, nullable=False)
    review = db.Column(db.Text)
    review_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    professional_id = db.Column(db.Integer, db.ForeignKey('professionals.id'), nullable=True)  # Add foreign key to ServiceProfessional
    

    service_request = db.relationship('ServiceRequest', back_populates='reviews')
    professional = db.relationship('ServiceProfessional', back_populates='reviews')  # Link the review to ServiceProfessional

    def __repr__(self):
        return f"<Review {self.id}>"

