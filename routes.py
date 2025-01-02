from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from models import db, Users, Customer, ServiceProfessional, ServiceRequest, Category, Service, ServiceHistory, Review
from flask_login import login_manager, login_user, logout_user, current_user, login_required, LoginManager
from functools import wraps
import os
from werkzeug.utils import secure_filename
from flask import jsonify
import mimetypes
from datetime import datetime
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'pdf'

def is_pdf(file_path):
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type == 'application/pdf'

ALLOWED_EXTENSIONS = {'pdf'}



main = Blueprint('main', __name__)


def auth_required(allowed_roles=None):
    def decorator(func):
        @wraps(func)
        def inner(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('main.signin'))
            if allowed_roles and current_user.role not in allowed_roles:
                flash('Access denied.', 'danger')
                return redirect('/')
            return func(*args, **kwargs)
        return inner
    return decorator
@main.route('/')
@auth_required(allowed_roles=['admin', 'professional', 'customer'])
def home():
    user=Users.query.get(current_user.id)
    if user.role=='admin':
        return redirect('/admin_home')
    elif user.role=='customer':
        return redirect('/customer_home')
    elif user.role=='professional':
        return redirect('/professional_home')
    


@main.route('/register_customer', methods=['GET', 'POST'])
def register_customer():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        email = request.form.get('email')        
        password = generate_password_hash(request.form.get('password'))  # Password hashing
        address = request.form.get('address')
        phone_number = request.form.get('phone_number')
        state = request.form.get('state')
        pincode = request.form.get('pincode')


        # Check if username or email already exists
        existing_user = Users.query.filter((Users.username == username) | (Users.email == email)).first()
        if existing_user:
            if existing_user.username == username:
                flash('Username already exists. Please choose a different one.', 'danger')
            elif existing_user.email == email:
                flash('Email already exists. Please choose a different one.', 'danger')
            return redirect(url_for('main.register_customer'))

        user = Users(email=email, username=username, password=password, name=name, phone_number=phone_number,state=state,pincode=pincode, address=address, role='customer')
        try:
            db.session.add(user)
            db.session.commit()

            customer = Customer(user_id=user.id)
            db.session.add(customer)
            db.session.commit()

            flash('Registration successful! Please sign in to continue.', 'success')
            return redirect(url_for('main.signin'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('main.register_customer'))

    return render_template('/register_customer.html')

@main.route('/register_service_professional', methods=['GET', 'POST'])
def register_professional():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        email = request.form.get('email')        
        password = generate_password_hash(request.form.get('password'))  # Password hashing
        address = request.form.get('address')
        phone_number = request.form.get('phone_number')
        state = request.form.get('state')
        pincode = request.form.get('pincode')
        service_type = request.form.get('service_type')
        experience = request.form.get('experience')


        # Check if username or email already exists
        existing_user = Users.query.filter((Users.username == username) | (Users.email == email)).first()
        if existing_user:
            if existing_user.username == username:
                flash('Username already exists. Please choose a different one.', 'danger')
            elif existing_user.email == email:
                flash('Email already exists. Please choose a different one.', 'danger')
            return redirect(url_for('main.register_professional'))
        
        # Handle PDF upload
        if 'pdf_file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['pdf_file']
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            if not os.path.exists('static/uploads'):
                os.makedirs('static/uploads')
            file_path = os.path.join('static/uploads', filename)
            file.save(file_path)
            file_path = f'uploads/{filename}' 


            # Create a new user and service professional
            user = Users(email=email, username=username, password=password, name=name, phone_number=phone_number,
                         state=state, pincode=pincode, address=address, role='professional')
            db.session.add(user)
            db.session.commit() 

            cat = Category.query.filter_by(name=service_type).first()

            newprofessional = ServiceProfessional(user_id=user.id, service_type=service_type, experience=experience, 
                                               category_id=cat.id, file_path=file_path)
            db.session.add(newprofessional)
            db.session.commit()

            flash('Registration successful! Please wait for admin approval.', 'success')
            return redirect(url_for('main.signin'))  
        else:
            flash('Error occured, Please upload you document again', 'danger')
            return redirect(url_for('main.register_professional'))

    category = Category.query.all()
    return render_template('/register_service_professional.html', category=category)


@main.route('/signin', methods=['GET', 'POST'])
def signin():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect('/') 
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        user = Users.query.filter_by(username=username, role=role).first()
        if user and role == 'admin' and password== 'admin' and user.is_admin:
            login_user(user)
            flash(f'Welcome {user.name}, you are logged in!', 'success')
            return redirect('/admin_home')
        if user and check_password_hash(user.password, password): 
            if (role == 'professional' and user.professional_profile and user.professional_profile.status == 'approved' ) or role == 'customer':
                if user.is_blocked:
                    flash("You are blocked by admin", "danger")
                    return redirect(url_for('main.signin'))
                login_user(user)
                flash(f'Welcome {user.name}, you are logged in!', 'success')
                return redirect('/')
            elif role == 'professional' and user.professional_profile.status == 'pending':
                logout_user()
                flash('Your registration is pending approval.', 'info')
                return redirect(url_for('main.signin'))
            elif role == 'professional' and user.professional_profile.status == 'rejected':
                flash('Your registration was rejected.', 'danger')
                return redirect(url_for('main.signin'))
        else:
            flash('Invalid username, role, or password.', 'danger')

        return redirect('/signin')
    return render_template('/signin.html')

@main.route('/admin/approve/<int:id>', methods=['POST'])
@auth_required(allowed_roles=['admin'])
def approve_user(id):
    professional = ServiceProfessional.query.get(id)
    if not professional:
        flash('Professional not found.', 'danger')
        return redirect(url_for('main.admin_home'))
    
    professional.status = 'approved'
    db.session.commit()
    flash(f'Professional {professional.user.name} has been approved.', 'success')
    return redirect(url_for('main.admin_home'))


@main.route('/admin/reject/<int:id>', methods=['POST'])
@auth_required(allowed_roles=['admin'])
def reject_user(id):
    # Fetch the professional record
    professional = ServiceProfessional.query.filter_by(id=id).first()

    if not professional:
        flash("Professional not found.", "danger")
        return redirect('/admin_home')

    # Fetch the associated user record
    user = Users.query.filter_by(id=professional.user_id).first()

    if not user:
        flash("User associated with the professional not found.", "danger")
        return redirect('/admin_home')

    # Store the professional's name for the flash message
    professional_name = user.name

    # Delete the professional first to avoid integrity errors
    db.session.delete(professional)
    db.session.commit()

    # Delete the user
    db.session.delete(user)
    db.session.commit()

    flash(f'Professional {professional_name} verification has been removed.', 'warning')
    return redirect('/admin_home')


@main.route('/admin_home', methods=['GET'])
@auth_required(allowed_roles=['admin'])
def admin_home():
    customer= Customer.query.all()
    # Get search parameters from the query
    search_type = request.args.get('search_type', '')  
    search_query = request.args.get('search_query', '').strip() 
    service_requests_query = ServiceRequest.query
    if search_query and search_type:
        if search_type == 'service_name':
            service_requests_query = service_requests_query.join(Service).filter(Service.name.ilike(f'%{search_query}%'))
        elif search_type == 'customer_name':
            service_requests_query = service_requests_query.join(Customer).join(Users).filter(Users.name.ilike(f'%{search_query}%'))
        elif search_type == 'professional_name':
            service_requests_query = service_requests_query.join(ServiceProfessional).join(Users).filter(Users.name.ilike(f'%{search_query}%'))
        elif search_type == 'status':
            service_requests_query = service_requests_query.filter(ServiceRequest.service_status.ilike(f'%{search_query}%'))



    # Execute query
    service_requests = service_requests_query.all()

    # Fetch other data
    cat = Category.query.all()
    ser = Service.query.all()
    prof = ServiceProfessional.query.all()
    ser_history = ServiceHistory.query.all()

    return render_template(
        '/admin_home.html',
        categories=cat,
        professionals=prof,
        services=ser,
        service_requests=service_requests,
        service_history=ser_history,
        search_type=search_type,
        search_query=search_query,
        customer=customer
    )




@main.route('/customer_home', methods=['GET', 'POST'])
@auth_required(allowed_roles=['customer'])
def customer_home():
    categories = Category.query.all()

    # Retrieve the Customer object associated with the current user
    customer = Customer.query.filter_by(user_id=current_user.id).first()
    if not customer:
        flash("Customer profile not found.", "danger")
        return redirect(url_for('main.index'))
    
    if current_user.is_blocked:
        logout_user()
        flash("You are blocked by admin", "danger")
        return redirect(url_for('main.signin'))

    filter_status = request.args.get('filter_status', 'all')

    if filter_status == 'all':
        service_requests = ServiceRequest.query.filter_by(customer_id=customer.id).all()
    else:
        service_requests = ServiceRequest.query.filter_by(customer_id=customer.id, service_status=filter_status).all()

    servicehistory = ServiceHistory.query.filter(
        ServiceHistory.service_request.has(customer_id=customer.id)
    ).all()

    return render_template(
        'customer_home.html',
        categories=categories,
        servicehistory=servicehistory,
        service_requests=service_requests,
        filter_status=filter_status
    )

@main.route('/professional_home')
@auth_required(allowed_roles=['professional'])
def professional_home():
    professional = ServiceProfessional.query.filter_by(user_id=current_user.id).first()
    user = Users.query.filter_by(id=current_user.id).first()
    if professional and professional.status == 'pending':
        flash("Your registration is pending approval.", "info")
        return redirect(url_for('main.signin'))
    
    elif professional and professional.status == 'rejected':
        flash("Your registration was rejected.", "danger")
        return redirect(url_for('main.signin'))
    
    elif professional and user.is_blocked:
        logout_user()
        flash("You are blocked by admin", "danger")
        return redirect(url_for('main.signin'))

    if professional:
        service_requests = ServiceRequest.query.filter(
            ServiceRequest.professional_id == professional.id,
            ServiceRequest.service_status.in_(['requested', 'assigned'])
        ).all()
        services = Service.query.filter_by(professional_id=professional.id).all()

        # Fetch service requests that are not "requested" for history
        service_history = ServiceRequest.query.filter(
            ServiceRequest.professional_id == professional.id,
            ServiceRequest.service_status != 'requested'
        ).all()
        closed_requests = ServiceRequest.query.filter(
            ServiceRequest.professional_id == professional.id,
            ServiceRequest.service_status == 'closed').all()
        review=Review.query.filter(Review.service_request.has(professional_id=professional.id)).all()
    else:
        service_requests = []
        services = []
        service_history = []

    return render_template(
        'professional_home.html',
        professional=professional,
        services=services,
        service_requests=service_requests,
        service_history=service_history,
        closed_requests=closed_requests,
        review=review
    )

@main.route('/customer/profile', methods=['GET'])
@login_required
def customer_profile():
    cust = Customer.query.filter_by(user_id=current_user.id).first()
    if not cust:
        flash("Profile not found!", "danger")
        return redirect(url_for('main.customer_home'))
    return render_template('customer_profile.html', customer=cust)

@main.route('/professional/profile', methods=['GET'])
@login_required
def professional_profile():
    prof = ServiceProfessional.query.filter_by(user_id=current_user.id).first()

    if not prof:
        flash("Professional profile not found.", "danger")
        return redirect(url_for('main.index'))
    
    return render_template('professional_profile.html', professional=prof)

@main.route('/edit_customer_profile', methods=['GET', 'POST'])
@auth_required(allowed_roles=['customer'])
def edit_customer_profile():
    # Get the current customer's profile
    customer = Customer.query.filter_by(user_id=current_user.id).first()

    if not customer:
        flash("Customer profile not found.", "danger")
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        # Retrieve form data
        name = request.form.get('name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        address = request.form.get('address')
        state = request.form.get('state')
        pincode = request.form.get('pincode')

        # Password fields
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')


        # Validate password change, if provided
        if current_password or new_password or confirm_password:
            if not current_password or not new_password or not confirm_password:
                flash("All password fields are required to update your password.", "danger")
                return redirect(url_for('main.edit_customer_profile'))
            
            if not check_password_hash(current_user.password, current_password):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for('main.edit_customer_profile'))
            
            if new_password != confirm_password:
                flash("New password and confirm password do not match.", "danger")
                return redirect(url_for('main.edit_customer_profile'))
            
            current_user.password = generate_password_hash(new_password)
            flash("Your password has been updated successfully!", "success")

        current_user.name = name
        current_user.email = email
        current_user.phone_number = phone_number
        current_user.address = address
        current_user.state = state
        current_user.pincode = pincode

        db.session.commit()
        flash("Your profile has been updated successfully", "success")
        return redirect(url_for('main.customer_home'))

    return render_template('edit_customer_profile.html', customer=customer)


@main.route('/edit_professional_profile', methods=['GET', 'POST'])
@auth_required(allowed_roles=['professional'])
def edit_professional_profile():
    professional = ServiceProfessional.query.filter_by(user_id=current_user.id).first()

    if not professional:
        flash("Professional profile not found.", "danger")
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        experience = request.form.get('experience')
        description = request.form.get('description')
        address=request.form.get('address')
        state=request.form.get('state')
        pincode=request.form.get('pincode')

        # Password fields
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Validate required fields
        if not name or not email or not experience:
            flash("Name, email, service type, and experience are required.", "danger")
            return redirect(url_for('main.edit_professional_profile'))

        # Validate password change, if provided
        if current_password or new_password or confirm_password:
            if not current_password or not new_password or not confirm_password:
                flash("All password fields are required to update your password.", "danger")
                return redirect(url_for('main.edit_professional_profile'))

            if not check_password_hash(current_user.password, current_password):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for('main.edit_professional_profile'))

            if new_password != confirm_password:
                flash("New password and confirm password do not match.", "danger")
                return redirect(url_for('main.edit_professional_profile'))

            # Update password
            current_user.password = generate_password_hash(new_password)
            flash("Your password has been updated successfully!", "success")

        # Update professional and user details
        current_user.name = name
        current_user.email = email
        current_user.phone_number = phone_number
        professional.experience = int(experience) if experience.isdigit() else 0
        professional.description = description
        professional.address=address
        professional.state=state
        professional.pincode=pincode

        # Commit changes to the database
        db.session.commit()
        flash("Your profile has been updated successfully", "success")
        return redirect(url_for('main.professional_home'))

    return render_template('edit_professional_profile.html', professional=professional)





@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/signin')

@main.route('/add_servicecategory', methods=['GET', 'POST'])
@auth_required(allowed_roles=['admin'])
def add_servicecategory():
    if request.method == 'POST':
        name = request.form.get('name')
        price = request.form.get('base_price')
    
        if Category.query.filter_by(name=name).first():
            flash('Service already exists', 'danger')
            return redirect('/add_servicecategory')
        category= Category(name=name, base_price=price)
        db.session.add(category)
        db.session.commit()

        flash('Service added successfully!', 'success')
        return redirect('/admin_home')
    return render_template('/add_servicecategory.html')

@main.route('/category/<int:category_id>/services')
@auth_required(allowed_roles=['customer'])
def services_by_category(category_id):
    # Fetch the category by its ID
    category = Category.query.get(category_id)
    services = Service.query.filter_by(category_id=category_id).all()
    current_date=datetime.utcnow().strftime('%Y-%m-%d')  # Pass current date
    return render_template('services_by_category.html', category=category, services=services,current_date=current_date)

@main.route('/admin/edit_servicecategory/<int:id>', methods=['GET', 'POST'])
@auth_required(allowed_roles=['admin'])
def edit_category(id):
    category = Category.query.get(id)
    if request.method == 'POST':
        name = request.form.get('name')
        base_price = request.form.get('base_price')
        category.name = name
        category.base_price = base_price

        db.session.add(category)
        db.session.commit()
        flash('Service updated successfully!', 'success')
        return redirect('/admin_home')
    return render_template('/edit_servicecategory.html', category=category)





@main.route('/admin/servicecategory/delete/<int:id>')
@auth_required(allowed_roles=['admin'])
def delete_servicecategory(id):
    category = Category.query.get(id)
    db.session.delete(category)
    db.session.commit()
    flash('Service deleted successfully!', 'success')
    return redirect('/admin_home')


@main.route('/category/<int:id>/add-service', methods=['GET', 'POST'])
@auth_required(allowed_roles=['professional'])
def append_service(id):
    # Get the logged-in professional
    professional = ServiceProfessional.query.filter_by(user_id=current_user.id).first()
    category = Category.query.get_or_404(id)
    if not professional:
        flash("Professional profile not found.", "danger")
        return redirect(url_for('main.professional_home'))
    elif professional.status == 'pending':
        flash("Your registration is pending approval.", "info")
        return redirect(url_for('main.signin'))
    elif professional.status == 'rejected':
        flash("Your registration was rejected.", "danger")
        return redirect(url_for('main.signin'))
    elif current_user.is_blocked:
        logout_user()
        flash("You are blocked by admin", "danger")
        return redirect(url_for('main.signin'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        price = float(request.form.get('price'))
        time_required = request.form.get('time_required')
        description = request.form.get('description')

        if price < category.base_price:
            flash(f"Price cannot be below the base price of ₹{category.base_price}.", "danger")
            return render_template('add_service.html', category=category)

        service = Service(
            name=name,
            price=price,
            time_required=time_required,
            description=description,
            category_id=category.id,
            professional_id=professional.id
        )

        db.session.add(service)
        db.session.commit()

        flash('Service added successfully!', 'success')
        return redirect('/professional_home')

    return render_template('add_service.html', category=category)

@main.route('/admin/service/delete/<int:id>')
@auth_required(allowed_roles=['admin'])
def delete_services(id):
    service = Service.query.get(id)
    db.session.delete(service)
    db.session.commit()
    flash('Service deleted successfully!', 'success')
    return redirect('/admin_home')


@main.route('/professional/service/delete/<int:id>')
@auth_required(allowed_roles=['professional'])
def delete_service(id):
    service = Service.query.get(id)
    db.session.delete(service)
    db.session.commit()
    flash('Service deleted successfully!', 'success')
    return redirect('/professional_home')

@main.route('/edit_service/<int:id>', methods=['GET', 'POST'])
@auth_required(allowed_roles=['professional'])
def edit_service(id):
    service = Service.query.get(id)
    if request.method == 'POST':
        name = request.form.get('name')
        price = request.form.get('price')
        time_required = request.form.get('time_required')
        description = request.form.get('description')

        service.name = name
        service.price = price
        service.time_required = time_required
        service.description = description

        db.session.add(service)
        db.session.commit()
        flash('Service updated successfully!', 'success')
        return redirect('/professional_home')
    return render_template('edit_service.html', service=service)


@main.route('/admin/professional/delete/<int:id>', methods=['GET'])
@auth_required(allowed_roles=['admin'])
def delete_professional(id):
    professional = ServiceProfessional.query.filter_by(id=id).first()

    user = Users.query.filter_by(id=professional.user_id).first()
    if not user:
        flash("User associated with the professional not found.", "danger")
        return redirect('/admin_home')

    reviews = Review.query.filter_by(professional_id=professional.id).all()
    for review in reviews:
        db.session.delete(review)

    services = Service.query.filter_by(professional_id=professional.id).all()
    for service in services:
        db.session.delete(service)

    db.session.delete(professional)
    db.session.commit()
    db.session.delete(user)
    db.session.commit()

    flash(f"Professional {user.name} and their services have been removed.", "success")
    return redirect('/admin_home')


@main.route('/admin/customer/delete/<int:id>', methods=['GET'])
@auth_required(allowed_roles=['admin'])
def delete_customer(id):
    customer = Customer.query.filter_by(id=id).first()


    user = Users.query.filter_by(id=customer.user_id).first()
    if not user:
        flash("User associated with the customer not found.", "danger")
        return redirect('/admin_home')

    service_requests = ServiceRequest.query.filter_by(customer_id=customer.id).all()
    for request in service_requests:
        reviews = Review.query.filter_by(service_request_id=request.id).all()
        for review in reviews:
            db.session.delete(review)

    db.session.delete(customer)
    db.session.commit()
    db.session.delete(user)
    db.session.commit()

    flash(f"Customer {user.name} has been removed.", "success")
    return redirect('/admin_home')

@main.route('/delete_customer_profile', methods=['GET'])
@auth_required(allowed_roles=['customer'])
def delete_customer_profile():
    customer = Customer.query.filter_by(user_id=current_user.id).first()
    if not customer:
        flash("Customer profile not found.", "danger")
        return redirect(url_for('main.customer_home'))
    user = Users.query.filter_by(id=current_user.id).first()
    db.session.delete(customer)
    db.session.commit()
    db.session.delete(user)
    db.session.commit()
 
    flash("Your profile has been removed.", "success")
    return redirect(url_for('main.signin'))

@main.route('/delete_professional_profile', methods=['GET'])
@auth_required(allowed_roles=['professional'])
def delete_professional_profile():
    professional = ServiceProfessional.query.filter_by(user_id=current_user.id).first()
    if not professional:
        flash("Professional profile not found.", "danger")
        return redirect(url_for('main.professional_home'))
    user = Users.query.filter_by(id=current_user.id).first()
    db.session.delete(professional)
    db.session.commit()
    db.session.delete(user)
    db.session.commit()
    flash("Your profile has been removed.", "success")
    return redirect(url_for('main.signin'))


@main.route('/admin/block/<int:id>', methods=['POST'])
@auth_required(allowed_roles=['admin'])
def block_professional(id):
    professional = ServiceProfessional.query.get(id)
    if not professional:
        flash('Professional not found.', 'danger')
        return redirect(url_for('main.admin_home'))
    user = Users.query.get(professional.user_id)
    if not user:
        flash('User associated with the professional not found.', 'danger')
        return redirect(url_for('main.admin_home'))
    user.is_blocked = True
    db.session.commit()
    flash(f'Professional {user.name} has been blocked.', 'warning')
    return redirect(url_for('main.admin_home'))

@main.route('/admin/unblock/<int:id>', methods=['POST'])
@auth_required(allowed_roles=['admin'])
def unblock_professional(id):
    professional = ServiceProfessional.query.get(id)
    if not professional:
        flash('Professional not found.', 'danger')
        return redirect(url_for('main.admin_home'))
    user = Users.query.get(professional.user_id)
    if not user:
        flash('User associated with the professional not found.', 'danger')
        return redirect(url_for('main.admin_home'))
    user.is_blocked = False
    db.session.commit()
    flash(f'Professional {user.name} has been unblocked.', 'success')
    return redirect(url_for('main.admin_home'))

@main.route('/admin/block_customer/<int:id>', methods=['GET','POST'])
@auth_required(allowed_roles=['admin'])
def block_customer(id):
    customer = Customer.query.get(id)
    if not customer:
        flash('Customer not found.', 'danger')
        return redirect(url_for('main.admin_home'))
    user = Users.query.get(customer.user_id)
    if not user:
        flash('User associated with the customer not found.', 'danger')
        return redirect(url_for('main.admin_home'))
    user.is_blocked = True
    db.session.commit()
    flash(f'Customer {user.name} has been blocked.', 'warning')
    return redirect(url_for('main.admin_home'))

@main.route('/admin/unblock_customer/<int:id>', methods=['GET','POST'])
@auth_required(allowed_roles=['admin'])
def unblock_customer(id):
    customer = Customer.query.get(id)
    if not customer:
        flash('Customer not found.', 'danger')
        return redirect(url_for('main.admin_home'))
    user = Users.query.get(customer.user_id)
    if not user:
        flash('User associated with the customer not found.', 'danger')
        return redirect(url_for('main.admin_home'))
    user.is_blocked = False
    db.session.commit()
    flash(f'Customer {user.name} has been unblocked.', 'success')
    return redirect(url_for('main.admin_home'))

@main.route('/admin/service_details/<int:id>')
@auth_required(allowed_roles=['admin'])
def service_details(id):
    category = Category.query.get(id)
    service = Service.query.filter_by(category_id=category.id).all()
    return render_template('/service_details.html',category=category , services=service)

@main.route('/admin/professional_details/<int:id>')
@auth_required(allowed_roles=['admin'])
def professional_details(id):
    professional = ServiceProfessional.query.get(id)
    return render_template('/professional_details.html', professional=professional)

@main.route('/admin/customer_details/<int:id>', methods=['GET'])
@login_required
@auth_required(allowed_roles=['admin'])
def customer_details(id):
    customer = Customer.query.get(id)
    if not customer:
        flash("Customer not found.", "danger")
        return redirect(url_for('main.admin_dashboard'))

    # Aggregate service request data
    service_requests = customer.service_requests
    status_counts = {
        "requested": len([req for req in service_requests if req.service_status == "requested"]),
        "closed": len([req for req in service_requests if req.service_status == "closed"]),
        "assigned": len([req for req in service_requests if req.service_status == "assigned"]),
        "rejected": len([req for req in service_requests if req.service_status == "rejected"]),
        "cancelled": len([req for req in service_requests if req.service_status == "cancelled"])
    }

    # Render the template with status_counts
    return render_template('customer_details.html', customer=customer, status_counts=status_counts)

@main.route('/service_details/<int:id>')
@auth_required(allowed_roles=['customer'])
def service_detail(id):
    service = Service.query.get(id)
    current_date=datetime.utcnow().strftime('%Y-%m-%d')  # Pass current date

    return render_template('service_detail.html', service=service,current_date=current_date)


@main.route('/book-service', methods=['POST'])
@login_required
@auth_required(allowed_roles=['customer'])
def book_service():
    ser_id = request.form.get('service_id')
    prof_id = request.form.get('professional_id')
    date_of_request = request.form.get('date_of_request')  # Capture the selected date

    service = Service.query.get(ser_id)
    professional = ServiceProfessional.query.get(prof_id)

    if not service or not professional:
        flash("Invalid service or professional selection.", "danger")
        return redirect(url_for('main.customer_home'))

    if professional.id != service.professional_id:
        flash("The selected service does not belong to the selected professional.", "danger")
        return redirect(url_for('main.customer_home'))

    if not ser_id or not prof_id or not date_of_request:
        flash("Invalid service, professional, or date selection.", "danger")
        return redirect(url_for('main.customer_home'))

    try:
        # Validate and parse the date
        parsed_date = datetime.strptime(date_of_request, '%Y-%m-%d')
    except ValueError:
        flash("Invalid date format. Please select a valid date.", "danger")
        return redirect(url_for('main.customer_home'))

    customer = Customer.query.filter_by(user_id=current_user.id).first()

    # Create the service request with the selected date
    service_request = ServiceRequest(
        customer_id=customer.id,
        professional_id=prof_id,
        service_id=ser_id,
        service_status='requested',
        date_of_request=parsed_date
    )
    db.session.add(service_request)
    db.session.commit()

    flash("Service request submitted successfully!", "success")
    return redirect(url_for('main.booking_confirmation'))



@main.route('/booking-confirmation')
def booking_confirmation():
    return render_template('booking_confirmation.html')

@main.route('/reopen-service/<int:id>', methods=['POST'])
@login_required
@auth_required(allowed_roles=['customer'])
def reopen_service(id):
    ser_request = ServiceRequest.query.get(id)
    if not ser_request:
        flash("Service request not found.", "danger")
        return redirect(url_for('main.customer_home'))

    if ser_request.customer_id != current_user.customer_profile.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('main.customer_home'))
    #delete review
    review = Review.query.filter_by(service_request_id=id).first()
    if review:
        db.session.delete(review)
        db.session.commit()

    ser_request.service_status = 'requested'
    ser_request.date_of_request = datetime.utcnow()
    ser_request.date_of_completion=None
    db.session.commit()
    flash("Service request reopened successfully!", "success")
    return redirect(url_for('main.customer_home'))


@main.route('/customer/service-history')
def customer_service_history():
    user=Users.query.get(current_user.id)
    customer_id = user.customer_profile.id
    service_requests = ServiceRequest.query.filter_by(customer_id=customer_id).all()
    return render_template('customer_service_history.html', service_requests=service_requests)

@main.route('/service_professional/service-history')
def professional_service_history():
    professional_id = current_user.professional_profile.id
    service_requests = ServiceRequest.query.filter_by(professional_id=professional_id).all()
    return render_template('professional_service_history.html', service_requests=service_requests)


@main.route('/update-request-status', methods=['POST'])
@login_required
@auth_required(allowed_roles=['professional'])
def update_request_status():
    request_id = request.form.get('request_id')
    action = request.form.get('action')

    service_request = ServiceRequest.query.get(request_id)
    if not service_request:
        flash("Service request not found.", "danger")
        return redirect(url_for('main.professional_home'))

    professional_profile = current_user.professional_profile
    if not professional_profile or service_request.professional_id != professional_profile.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('main.professional_home'))

    if action == 'accept':
        service_request.service_status = 'assigned'
        new_history = ServiceHistory(
            service_request_id=request_id,
            professional_id=professional_profile.id, 
            service_status='assigned',
            remarks="Service accepted",
            professional_name=professional_profile.user.name,
            service_name=service_request.service.name,
            customer_name=service_request.customer.user.name
        )
        db.session.add(new_history)
        flash("Service request accepted and added to service history.", "success")

    elif action == 'reject':
        service_request.service_status = 'rejected'
        date_of_completion = datetime.utcnow()
        new_history = ServiceHistory(
            service_request_id=request_id,
            professional_id=professional_profile.id, 
            service_status='rejected',
            remarks="Service rejected",
            date_of_completion=date_of_completion,
            professional_name=professional_profile.user.name,
            service_name=service_request.service.name,
            customer_name=service_request.customer.user.name
        )
        db.session.add(new_history)
        flash("Service request rejected.", "warning")

    else:
        flash("Invalid action.", "danger")

    db.session.commit()
    return redirect(url_for('main.professional_home'))


@main.route('/complete_service', methods=['POST'])
@login_required
@auth_required(allowed_roles=['professional'])
def complete_service():
    # Fetch the service request ID from the form
    service_request_id = request.form.get('service_request_id')
    service_request = ServiceRequest.query.get(service_request_id)

    # Handle invalid service request
    if not service_request:
        flash("Service request not found.", "danger")
        return redirect(url_for('main.professional_home'))

    # Ensure the logged-in professional is authorized
    professional = ServiceProfessional.query.filter_by(user_id=current_user.id).first()
    if not professional or service_request.professional_id != professional.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('main.professional_home'))

    # Update service request status
    service_request.service_status = 'completed'
    service_request.date_of_completion = datetime.utcnow()

    # Check if service history exists and update/create it
    service_history = ServiceHistory.query.filter_by(service_request_id=service_request_id).first()
    if service_history:
        service_history.remarks = "Service Completed"
        service_history.date_of_completion = datetime.utcnow()
        remarks="Service completed by professional",

    else:
        service_history = ServiceHistory(
            service_request_id=service_request_id,
            professional_id=service_request.professional_id,
            date_of_request=service_request.date_of_request,
            service_status='completed',
            date_of_completion=datetime.utcnow(),
            remarks="Service completed by professional",
            professional_name=professional.user.name,
            service_name=service_request.service.name,
            customer_name=service_request.customer.user.name
        )
        db.session.add(service_history)

    # Commit changes to the database
    db.session.commit()
    flash("Service successfully completed!", "success")
    return redirect(url_for('main.professional_home'))



@main.route('/close-service', methods=['POST'])
@login_required
@auth_required(allowed_roles=['customer'])
def close_service():
    service_request_id = request.form.get('service_request_id')
    review_text = request.form.get('review')
    rating = request.form.get('rating')

    if not service_request_id or not review_text or not rating:
        flash("Review text and rating are required.", "danger")
        return redirect(url_for('main.customer_home'))

    customer = Customer.query.filter_by(user_id=current_user.id).first()
    service_request = ServiceRequest.query.get(service_request_id)

    if not service_request or service_request.customer_id != customer.id:
        flash("Unauthorized action or service request not found.", "danger")
        return redirect(url_for('main.customer_home'))

    review = Review.query.filter_by(service_request_id=service_request_id).first()
    if review:
        flash("You have already submitted a review for this service.", "warning")
    else:
        review = Review(
            service_request_id=service_request_id,
            review=review_text,
            rating=float(rating),
            professional_id=service_request.professional_id
        )
        db.session.add(review)

        professional = service_request.professional
        if professional:
            professional.total_ratings += 1
            professional.rating = (
                (professional.rating * (professional.total_ratings - 1)) + float(rating)
            ) / professional.total_ratings

    service_request.service_status = 'closed'
    if not service_request.date_of_completion:
        service_request.date_of_completion = datetime.utcnow()
    service_history = ServiceHistory.query.filter_by(service_request_id=service_request_id).first()
    if service_history:
        service_history.remarks = "Service closed with review"
        if not service_history.date_of_completion:
            service_history.date_of_completion = datetime.utcnow()
    else:
        # Create new history entry if it doesn't exist
        service_history = ServiceHistory(
            service_request_id=service_request_id,
            professional_id=service_request.professional_id,
            date_of_request=service_request.date_of_request,
            service_status='closed',
            date_of_completion=datetime.utcnow(),
            remarks="Service closed by customer with review"
        )
        db.session.add(service_history)

    # Commit the changes
    try:
        db.session.commit()
        flash("Service successfully closed and review submitted!", "success")
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while closing the service. Please try again.", "danger")

    return redirect(url_for('main.customer_home'))



@main.route('/cancel_service', methods=['POST'])
@login_required
@auth_required(allowed_roles=['customer'])
def cancel_service():
    service_request_id = request.form.get('service_request_id')
    print(f"Service Request ID received: {service_request_id}") 

    customer = Customer.query.filter_by(user_id=current_user.id).first()
    if not customer:
        flash("Customer profile not found. Please register as a customer.", "danger")
        return redirect(url_for('main.customer_home'))

    service_request = ServiceRequest.query.get(service_request_id)
    if not service_request or service_request.customer_id != customer.id:
        flash("Unauthorized action or service request not found.", "danger")
        return redirect(url_for('main.customer_home'))

    print(f"Customer ID: {customer.id}, Service Request Customer ID: {service_request.customer_id}")  # Debugging

    if service_request.service_status in ['closed', 'cancelled']:
        flash(f"Cannot cancel a service that is already {service_request.service_status}.", "danger")
        return redirect(url_for('main.customer_home'))

    service_request.service_status = 'cancelled'
    service_request.date_of_completion = datetime.utcnow()

    # Ensure all required fields in `ServiceHistory` are populated
    service_name = service_request.service.name if service_request.service else "Unknown"
    professional_name = service_request.professional.user.name if service_request.professional and service_request.professional.user else "Unknown"
    customer_name = customer.user.name if customer.user else "Unknown"

    service_history = ServiceHistory.query.filter_by(service_request_id=service_request_id).first()
    if service_history:
        service_history.remarks = "Service cancelled"
        service_history.date_of_completion = datetime.utcnow()
        service_history.service_status = 'cancelled'
    else:
        service_history = ServiceHistory(
            service_request_id=service_request_id,
            professional_id=service_request.professional_id,
            date_of_request=service_request.date_of_request,
            service_status='cancelled',
            date_of_completion=datetime.utcnow(),
            remarks="Service cancelled",
            professional_name=professional_name,
            service_name=service_name,
            customer_name=customer_name
        )
        db.session.add(service_history)

    try:
        db.session.commit()
        flash("Service successfully cancelled!", "success")
    except Exception as e:
        db.session.rollback()
        print(f"Error during service cancellation: {str(e)}")  # Debugging
        flash("An error occurred while cancelling the service. Please try again.", "danger")

    return redirect(url_for('main.customer_home'))



@main.route('/submit-review/<int:service_request_id>', methods=['GET'])
@login_required
@auth_required(allowed_roles=['customer'])
def submit_review(service_request_id):
    customer = Customer.query.filter_by(user_id=current_user.id).first()
    service_request = ServiceRequest.query.get(service_request_id)

    if not service_request or service_request.customer_id != customer.id:
        flash("Unauthorized or invalid service request.", "danger")
        return redirect(url_for('main.customer_home'))
    date=datetime.utcnow()

    return render_template('submit_review.html', service_request=service_request,date=date)


@main.route('/search', methods=['GET'])
@login_required
@auth_required(allowed_roles=['customer'])
def search():
    query = request.args.get('query', '').strip()  
    filter_by = request.args.get('filter_by', 'service') 
    service=Service.query.all()
    results = []

    if query:  
        if filter_by == 'service':
            results = Service.query.filter(Service.name.ilike(f"%{query}%")).all()
        elif filter_by == 'professional':
            results = ServiceProfessional.query.filter(
                ServiceProfessional.user.has(Users.name.ilike(f"%{query}%"))
            ).all()
        elif filter_by == 'price':
            try:
                price = float(query)
                results = Service.query.filter(Service.price <= price).all()
            except ValueError:
                flash("Please enter a valid number for price.", "danger")
        elif filter_by == 'state':
            results = ServiceProfessional.query.filter(ServiceProfessional.user.has(Users.state.ilike(f"%{query}%"))).all()
    return render_template('search_results.html', results=results, query=query, filter_by=filter_by,service=service)

@main.route('/admin_search', methods=['GET'])
@login_required
@auth_required(allowed_roles=['admin'])
def admin_search():
    query = request.args.get('query', '').strip()  
    filter_by = request.args.get('filter_by', '')  

    results = []

    if query:  
        if filter_by == 'service':
            results = Service.query.filter(Service.name.ilike(f"%{query}%")).all()
        elif filter_by == 'professional':
            results = ServiceProfessional.query.filter(
                ServiceProfessional.user.has(Users.name.ilike(f"%{query}%"))
            ).all()
        elif filter_by == 'customer':
            results = Customer.query.filter(
                Customer.user.has(Users.name.ilike(f"%{query}%"))
            ).all()
        elif filter_by == 'state':
            results = ServiceProfessional.query.filter(ServiceProfessional.user.has(Users.state.ilike(f"%{query}%"))).all()

    return render_template('admin_search.html', results=results, query=query, filter_by=filter_by)

from datetime import datetime

@main.route('/search_professional_requests', methods=['GET', 'POST'])
@login_required
@auth_required(allowed_roles=['professional'])
def search_professional_requests():
    professional = ServiceProfessional.query.filter_by(user_id=current_user.id).first()
    if not professional:
        flash("Professional profile not found. Please register as a professional.", "danger")
        return redirect(url_for('main.professional_home'))

    filter_field = request.form.get('filter_field', '')
    search_value = request.form.get('search_value', '').strip()
    service_requests = []

    if request.method == 'POST' and filter_field and search_value:
        # Base query scoped to the logged-in professional
        service_requests_query = ServiceRequest.query.filter_by(professional_id=professional.id)

        if filter_field == 'state':
            service_requests_query = service_requests_query.join(Customer).join(Users).filter(
                Users.state.ilike(f"%{search_value}%")
            )
        elif filter_field == 'date':
            # Parse and normalize the date
            try:
                search_date = datetime.strptime(search_value.strip(), "%Y-%m-%d").date()
                service_requests_query = service_requests_query.filter(
                    func.date(ServiceRequest.date_of_request) == search_date
                )
            except ValueError:
                flash("Invalid date format. Please enter a valid date.", "danger")
                service_requests_query = service_requests_query.filter(False)  # Empty results
        elif filter_field == 'service_name':
            service_requests_query = service_requests_query.join(Service).filter(
                Service.name.ilike(f"%{search_value}%")
            )
        elif filter_field == 'customer_name':
            service_requests_query = service_requests_query.join(Customer).join(Users).filter(
                Users.name.ilike(f"%{search_value}%")
            )

        service_requests = service_requests_query.all()

    return render_template(
        'professional_search.html',
        service_requests=service_requests,
        filter_field=filter_field,
        search_value=search_value,
        professional=professional
    )





@main.route('/professional_summary', methods=['GET'])
@login_required
def professional_summary():
    service_requests=ServiceRequest.query.filter_by(professional_id=current_user.professional_profile.id).all()
    status_counts = {
        "requested": len(service_requests),
    }

    return render_template('professional_summary.html', servicerequest=service_requests, status_counts=status_counts)

from flask import jsonify
from flask_login import login_required, current_user




@main.route('/get_professional_data/<int:id>', methods=['GET'])
@login_required
def get_professional_data(id):
    professional = ServiceProfessional.query.get(id)

    if not professional:
        return jsonify({"error": "Professional not found"}), 404

    rating_counts = db.session.query(
        Review.rating,
        db.func.count(Review.rating)
    ).join(ServiceRequest, Review.service_request_id == ServiceRequest.id
    ).filter(
        ServiceRequest.professional_id == professional.id
    ).group_by(
        Review.rating
    ).all()

    rating_data = {f"{i}_stars": 0 for i in range(1, 6)}
    for rating, count in rating_counts:
        rating_data[f"{int(rating)}_stars"] = count

    print("Rating Data:", rating_data)

    service_requests = professional.service_requests
    service_request_data = {
        "received": len(service_requests),
        "assigned": len([req for req in service_requests if req.service_status == "assigned"]),
        "closed": len([req for req in service_requests if req.service_status == "closed"]),
        "rejected": len([req for req in service_requests if req.service_status == "rejected"]),
    }

    print("Service Request Data:", service_request_data)

    return jsonify({
        "ratings": rating_data,
        "service_requests": service_request_data
    })


@main.route('/get_summary_data', methods=['GET'])
@login_required
def get_summary_data():
    professional = ServiceProfessional.query.filter_by(user_id=current_user.id).first()

    if not professional:
        return jsonify({"error": "Professional not found"}), 404

    rating_counts = db.session.query(
        Review.rating, 
        db.func.count(Review.rating)
    ).join(ServiceRequest, Review.service_request_id == ServiceRequest.id
    ).filter(
        ServiceRequest.professional_id == professional.id
    ).group_by(
        Review.rating
    ).all()

    # Populate the ratings data
    rating_data = {f"{i}_stars": 0 for i in range(1, 6)}
    for rating, count in rating_counts:
        rating_data[f"{int(rating)}_stars"] = count

    # Service Requests Data
    service_requests = professional.service_requests
    service_request_data = {
        "received": len(service_requests),
        "assigned": len([req for req in service_requests if req.service_status == "assigned"]),
        "closed": len([req for req in service_requests if req.service_status == "closed"]),
        "rejected": len([req for req in service_requests if req.service_status == "rejected"])
    }

    # Return both datasets as JSON
    return jsonify({
        "ratings": rating_data,
        "service_requests": service_request_data
    })

@main.route('/customer_summary', methods=['GET'])
@auth_required(allowed_roles=['customer'])
def customer_summary():
    # Ensure the user is a customer
    customer = Customer.query.filter_by(user_id=current_user.id).first()
    if not customer:
        flash("Customer profile not found.", "danger")
        return redirect(url_for('main.index'))

    service_requests = ServiceRequest.query.filter_by(customer_id=customer.id).all()

    # Count the statuses for requested, closed, and assigned
    statuscount = {
        "requested": len([req for req in service_requests if req.service_status == "requested"]),
        "closed": len([req for req in service_requests if req.service_status == "closed"]),
        "assigned": len([req for req in service_requests if req.service_status == "assigned"]),
    }

    return render_template('customer_summary.html', status_counts=statuscount)


@main.route('/admin_summary', methods=['GET'])
@auth_required(allowed_roles=['admin'])
def admin_summary():
    service_requests = ServiceRequest.query.all()

    status_counts = {
        "requested": len([req for req in service_requests if req.service_status == "requested"]),
        "closed": len([req for req in service_requests if req.service_status == "closed"]),
        "assigned": len([req for req in service_requests if req.service_status == "assigned"]),
    }

    customer_ratings = Review.query.with_entities(Review.rating, db.func.count(Review.rating)).group_by(Review.rating).all()
    rating_distribution = {int(rating): count for rating, count in customer_ratings}

    # Ensure all rating keys (1-5) are present
    for i in range(1, 6):
        rating_distribution.setdefault(i, 0)

    return render_template(
        'admin_summary.html',
        status_counts=status_counts,
        rating_distribution=rating_distribution
    )

@main.route('/edit_date/<int:service_request_id>', methods=['GET', 'POST'])
@login_required
@auth_required(allowed_roles=['customer'])
def edit_date(service_request_id):
    # Retrieve the service request
    service_request = ServiceRequest.query.get(service_request_id)
    if not service_request:
        flash("Service request not found.", "danger")
        return redirect(url_for('main.customer_home'))

    # Ensure the logged-in user is the owner of the service request
    customer = Customer.query.filter_by(user_id=current_user.id).first()
    if not customer or service_request.customer_id != customer.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('main.customer_home'))

    if request.method == 'POST':
        new_date = request.form.get('new_date')
        try:
            # Validate and update the date
            service_request.date_of_request = datetime.strptime(new_date, '%Y-%m-%d')
            db.session.commit()
            flash("Date of request updated successfully!", "success")
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", "danger")
        return redirect(url_for('main.customer_home'))

    return render_template('edit_date.html', service_request=service_request)
