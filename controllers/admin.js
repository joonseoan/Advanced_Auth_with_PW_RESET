const Product = require('../models/product');

exports.getAddProduct = (req, res, next) => {

  res.render('admin/edit-product', {
    pageTitle: 'Add Product',
    path: '/admin/add-product',
    editing: false
    // isAuthenticated: req.session.isAuthenticated
  });
};

exports.postAddProduct = (req, res, next) => {
  const title = req.body.title;
  const imageUrl = req.body.imageUrl;
  const price = req.body.price;
  const description = req.body.description;
  const product = new Product({
    title: title,
    price: price,
    description: description,
    imageUrl: imageUrl,
    // ref is assined in schema
    // Better to use req.user
    userId: req.user
  });
  product
    .save()
    .then(result => {
      res.redirect('/admin/products');
    })
    .catch(err => {
      console.log(err);
    });
};

exports.getEditProduct = (req, res, next) => {
  const editMode = req.query.edit;
  if (!editMode) {
    return res.redirect('/');
  }
  const prodId = req.params.productId;
  Product.findById(prodId)
    .then(product => {
      if (!product) {
        return res.redirect('/');
      }
      res.render('admin/edit-product', {
        pageTitle: 'Edit Product',
        path: '/admin/edit-product',
        editing: editMode,
        product: product,
       // isAuthenticated: req.session.isAuthenticated
      });
    })
    .catch(err => console.log(err));
};

exports.postEditProduct = (req, res, next) => {
  const prodId = req.body.productId;
  const updatedTitle = req.body.title;
  const updatedPrice = req.body.price;
  const updatedImageUrl = req.body.imageUrl;
  const updatedDesc = req.body.description;

  Product.findById(prodId)
    .then(product => {

      // - block any other user to edit and delete products
      // even though we setup getProducts with find({userId: req.user_id })
      //  with at any tools, the hacker will be able to find products 
      //  then will be able to edit and delete products.


      // To protect the products from the malfunctions above,
      // we would need to add another safety function over here.
      if(product.userId.toString() !== req.user._id.toString()) {
        return res.redirect('/');
      }

      product.title = updatedTitle;
      product.price = updatedPrice;
      product.description = updatedDesc;
      product.imageUrl = updatedImageUrl;
      return product.save()
      .then(result => {
        console.log('UPDATED PRODUCT!');
        res.redirect('/admin/products');
      })
      .catch(err => console.log(err));
    });
};


exports.getProducts = (req, res, next) => {
  
  // 2) it is a way to find "products" uploaded by the current logged-in user.
  Product.find({ userId: req.user._id })
  
  // 1)
  // It is for the all logged-in user.
  // All logged-in user must not control edit and delete
  //  because the products are not uploaded by them.
  // It must be managed by a user whol uploaded the products.
  // Product.find()
    .then(products => {
      res.render('admin/products', {
        prods: products,
        pageTitle: 'Admin Products',
        path: '/admin/products',
        // isAuthenticated: req.session.isAuthenticated
      });
    })
    .catch(err => console.log(err));
};

exports.postDeleteProduct = (req, res, next) => {
  const prodId = req.body.productId;

  // we can delete product by using "deleteOne" which is from mongoose.
  // as explained abov, a user who uploaded this product can delete the product!!!!
  Product.deleteOne({ userId: req.user._id, _id: prodId })
  
  // Product.findByIdAndRemove(prodId)
    .then(() => {
      console.log('DESTROYED PRODUCT');
      res.redirect('/admin/products');
    })
    .catch(err => console.log(err));
};
