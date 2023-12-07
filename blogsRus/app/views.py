from flask import render_template, flash, request, redirect, url_for, request
from app import app, db, models
from .forms import LoginForm, SignUpForm, SearchForm
import time
import hashlib
from flask_login import login_user, LoginManager, login_required, logout_user, current_user
from sqlalchemy import func
import os

# Login managment initilisation
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@app.route('/', methods=['GET', 'POST'])
def home():

    form = SearchForm()
    if form.validate_on_submit():

        query = form.query.data.lower()
        foundBlogsIDs = []
        blogs = db.session.query(models.Blogs)

        taggedBlogsList = []
        if request.form.getlist('tagsSelect') != []:
            for tagID in request.form.getlist('tagsSelect'):
                taggedBlogs = db.session.query(
                    models.TagsLinker).filter_by(
                    tagID=tagID).all()
                for taggedBlog in taggedBlogs:
                    if taggedBlog not in taggedBlogsList:
                        taggedBlogsList.append(taggedBlog.blogID)

        for blog in blogs.all():
            # String comp to determine if search term is in title of blog
            if query in (
                    blog.title).lower() and (
                    blog.blogID in taggedBlogsList or taggedBlogsList == []):
                foundBlogsIDs.append(blog.blogID)

        for blog in blogs.all():
            # String comp to determine if search term name of user who wrote it
            # Note this is in seperate loop since prioritise title over author
            author = db.session.query(
                models.Users).filter_by(
                userID=blog.userID).first().username.lower()
            if query in author and blog.blogID not in foundBlogsIDs and (
                    blog.blogID in taggedBlogsList or taggedBlogsList == []):
                foundBlogsIDs.append(blog.blogID)

        for blog in blogs.all():
            # String comp to determine if search term is in description of blog
            # Note this is in seperate loop since prioritise title & author
            # over description
            if query in blog.description and blog.blogID not in foundBlogsIDs and (
                    blog.blogID in taggedBlogsList or taggedBlogsList == []):
                foundBlogsIDs.append(blog.blogID)

        foundBlogs = []
        for blogID in foundBlogsIDs:
            thisBlog = blogs.filter_by(blogID=blogID).first()
            author = db.session.query(
                models.Users).filter_by(
                userID=thisBlog.userID).first().username
            # Generate a list of tags attributed to each blog
            tagsList = []
            for tag in db.session.query(
                    models.TagsLinker).filter_by(
                    blogID=blogID).all():
                tagName = db.session.query(
                    models.Tags).filter_by(
                    tagID=tag.tagID).first()
                tagsList.append(tagName.tagName)
            foundBlogs.append({"title": thisBlog.title,
                               "description": thisBlog.description,
                               "content": thisBlog.content,
                               "timestamp": thisBlog.timestamp,
                               "author": author,
                               "blogID": blogID,
                               "imgLink": thisBlog.imgLink,
                               "tagsList": tagsList})

        return render_template('searchResults.html',
                               title='Search - ' + form.query.data,
                               stylesheet='./static/style/searchResults.css',
                               foundBlogs=foundBlogs)

    # Generate our latest blogs for homepage

    featuredBlogs = []
    for i in range(4):
        thisBlog = db.session.query(models.Blogs).filter_by(blogID=i).first()
        if thisBlog is not None:
            author = db.session.query(
                models.Users).filter_by(
                userID=thisBlog.userID).first().username
            # Generate a list of tags attributed to each blog
            tagsList = []
            for tag in db.session.query(
                    models.TagsLinker).filter_by(
                    blogID=i).all():
                tagName = db.session.query(
                    models.Tags).filter_by(
                    tagID=tag.tagID).first()
                tagsList.append(tagName.tagName)
            featuredBlogs.append({"title": thisBlog.title,
                                  "description": thisBlog.description,
                                  "author": author,
                                  "blogID": thisBlog.blogID,
                                  "imgLink": thisBlog.imgLink,
                                  "tagsList": tagsList})

    return render_template('home.html',
                           title='',
                           stylesheet='./static/style/home.css',
                           current_user=current_user,
                           featuredBlogs=featuredBlogs,
                           form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        foundUser = False
        # Check if username same as any in db
        for dbUser in db.session.query(models.Users).all():
            if form.username.data.lower() == dbUser.username.lower():
                foundUser = True
                # Check if password hashes match
                if hashlib.sha256((form.password.data).encode(
                        'utf-8')).hexdigest() == dbUser.passHash:
                    login_user(dbUser)
                    return redirect(url_for('home'))
                else:
                    flash("Password is incorrect")
        if not foundUser:
            flash("User does not exist")

    return render_template('login.html',
                           title='',
                           stylesheet='../static/style/login.css',
                           form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You Have Been Logged Out")
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        if form.password.data != form.confirm.data:
            flash("Passwords do not match")
        else:
            usernameTaken = False
            currentUsers = db.session.query(models.Users)
            for currentUser in currentUsers:
                # Note that since .lower(), if Bob is already a user then bob
                # cannot be used as a username, despite the fact that usernames
                # are stored with casing given
                if form.username.data.lower() == currentUser.username.lower():
                    flash("Username already taken try again")
                    usernameTaken = True
            if not usernameTaken:
                try:
                    nextUserID = db.session.query(
                        func.max(models.Users.userID)).scalar() + 1
                except BaseException:
                    nextUserID = 0

                db.session.add(
                    models.Users(
                        userID=nextUserID,
                        username=form.username.data,
                        passHash=hashlib.sha256(
                            (form.password.data).encode('utf-8')).hexdigest()))
                db.session.commit()

                # Send the user to the login page
                return redirect(url_for('login'))

    return render_template('signup.html',
                           title='',
                           stylesheet='../static/style/signup.css',
                           form=form)


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        if request.form['title'] == '':
            flash("Post must have a title")
        elif request.form['description'] == '':
            flash("Post must have description")
        elif request.form['content'] == '':
            flash("Post must have body content")
        else:
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            # if user does not select file, browser also submit an empty part
            # without filename
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)

            if file and allowed_file(file.filename):
                # Rather than using name of file as file name will use
                # timestamp since is more secure
                filename = str(int(time.time() * 1000)) + "." + \
                    file.filename.rsplit('.', 1)[1].lower()
                file.save(os.path.join('./app/static/uploads', filename))

                try:
                    nextBlogID = db.session.query(
                        func.max(models.Blogs.blogID)).scalar() + 1
                except BaseException:
                    nextBlogID = 0

                db.session.add(models.Blogs(
                    blogID=nextBlogID,
                    userID=current_user.userID,
                    timestamp=int(time.time()),
                    title=request.form['title'],
                    description=request.form['description'],
                    content=request.form['content'],
                    imgLink=filename
                ))

                for tagID in request.form.getlist('tags'):
                    try:
                        linkID = db.session.query(
                            func.max(models.TagsLinker.linkID)).scalar() + 1
                    except BaseException:
                        linkID = 0
                    db.session.add(models.TagsLinker(
                        linkID=linkID,
                        tagID=tagID,
                        blogID=nextBlogID))
                    db.session.commit()
                flash("Post Added")

                return redirect(url_for('createRedirect'))

    return render_template('create.html',
                           title='Create',
                           stylesheet='../static/style/create.css'
                           )


@app.route('/create', methods=['GET'])
@login_required
def createRedirect():
    return redirect(url_for('create'))


@app.route('/blog=<path:rest>', methods=['GET'])
def viewBlog(rest=None):

    blogID = request.base_url.split("=")[-1:][0]
    # Need to check this is actually a valid ID
    if bool(db.session.query(models.Blogs).filter_by(blogID=blogID).first()):
        thisBlog = db.session.query(
            models.Blogs).filter_by(
            blogID=blogID).first()
        author = db.session.query(
            models.Users).filter_by(
            userID=thisBlog.userID).first().username
        blogData = {
            "title": thisBlog.title,
            "description": thisBlog.description,
            "content": thisBlog.content,
            "timestamp": thisBlog.timestamp,
            "author": author,
            "blogID": blogID,
            "imgLink": thisBlog.imgLink}

    else:
        return render_template('blog.html',
                               title='Blog',
                               stylesheet='../static/style/blog.css',
                               blogData="False"
                               )

    return render_template('blog.html',
                           title='Blog',
                           stylesheet='../static/style/blog.css',
                           blogData=blogData
                           )


@app.route('/personal', methods=['GET', 'POST'])
@login_required
def personal():
    currentUserBlogData = []
    currentUsersBlogs = db.session.query(
        models.Blogs).filter_by(
        userID=current_user.userID).all()
    for thisBlog in currentUsersBlogs:
        author = db.session.query(
            models.Users).filter_by(
            userID=thisBlog.userID).first().username
        # Generate a list of tags attributed to each blog
        tagsList = []
        for tag in db.session.query(
                models.TagsLinker).filter_by(
                blogID=current_user.userID).all():
            tagName = db.session.query(
                models.Tags).filter_by(
                tagID=tag.tagID).first()
            tagsList.append(tagName.tagName)
        currentUserBlogData.append({"title": thisBlog.title,
                                    "description": thisBlog.description,
                                    "author": author,
                                    "blogID": thisBlog.blogID,
                                    "imgLink": thisBlog.imgLink,
                                    "tagsList": tagsList})

    if request.method == 'POST':
        blogID = request.form.get('delete').split(" - ")[1]
        db.session.query(models.Blogs).filter_by(blogID=blogID).delete()
        db.session.commit()
        flash("Post Deleted")
        return redirect(url_for('personal'))

    return render_template('personal.html',
                           title='',
                           stylesheet='./static/style/searchResults.css',
                           current_user=current_user,
                           currentUserBlogData=currentUserBlogData,
                           )


@login_manager.user_loader
def load_user(userID):
    return models.Users.query.get(userID)


@app.errorhandler(404)
def pageNotFound(e):
    return render_template('404.html', title="404"), 404
