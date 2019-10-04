const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user.js');
const APP_SECRET = require('../utils.js').APP_SECRET;

exports.signup = function (req, res) 
{
    let user = new User();
    if (!req.body || !req.body.name || !req.body.email || !req.body.password)
        return res.json(
        {
            errors: "Bad request! Supply POST data: name, email and password",
            code: 401
        })
    User.findOne({email: req.body.email}).then(oldUser => 
    {
        if (oldUser)
            return res.json({errors: "Email already exists", code: 427});
        user.name = req.body.name;
        user.email = req.body.email;

        bcrypt.hash(req.body.password, 10).then(pass =>
        {
            user.passwordHash = pass;
            const token = jwt.sign({email: user.email, id: user._id}, APP_SECRET)
            user.save(err =>
            {
                if (err)
                    return res.json(err);
                res.json(
                {
                    message: 'New user created',
                    data: 
                    {
                        name: user.name,
                        email: user.email,
                        token
                    }
                });
            });
        });
    });
};
// Handle view user info
exports.login = function (req, res) 
{
    if (!req.body || !req.body.email || !req.body.password)
        return res.json(
        {
            errors: "Bad request! Supply POST data: name, email and password",
            code: 401
        })
    User.findOne({email: req.body.email}).then(user => 
    {
        if (!user)
            return res.json({errors: "Email does not exist", code: 496});

        bcrypt.compare(req.body.password, user.passwordHash).then(valid =>
        {
            if (!valid)
                return res.json({errors: "Incorrect password", code: 419});

            const token = jwt.sign({email: user.email, id: user._id}, APP_SECRET);
            res.json(
            {
                message: 'Successful login',
                data:
                {
                    name: user.name,
                    email: user.email,
                    token
                }
            });
        });
    });
};



//
// The rest of CRUD for user model. Not used at the moment in this API
//
exports.update = function (req, res) {
User.findById(req.params.user_id, function (err, user) {
        if (err)
            res.send(err);
        user.name = req.body.name;
        user.email = req.body.email;
        user.save(function (err) {
            if (err)
                res.json(err);
            res.json({
                message: 'User Info updated',
                data: user
            });
        });
    });
};
// Handle delete user
exports.delete = function (req, res) {
    User.remove({
        _id: req.params.user_id
    }, function (err, user) {
        if (err)
            res.send(err);
res.json({
            status: "success",
            message: 'User deleted'
        });
    });
};



//reset password
exports.forgot = function(req, res, next) {
    async.waterfall([
      function(done) {
        crypto.randomBytes(20, function(err, buf) {
          var token = buf.toString('hex');
          done(err, token);
        });
      },
      function(token, done) {
        User.findOne({ email: req.body.email }, function(err, user) {
          if (!user) {
            res.json({errors: 'No account with that email address exists.', code: 420} );
            return res.redirect('/forgot');
          }
  
          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
  
          user.save(function(err) {
            done(err, token, user);
          });
        });
      },
      function(token, user, done) {
        var smtpTransport = nodemailer.createTransport('SMTP', {
          service: 'SendGrid',
          auth: {
            user: '!!! YOUR SENDGRID USERNAME !!!',
            pass: '!!! YOUR SENDGRID PASSWORD !!!'
          }
        });
        var mailOptions = {
          to: user.email,
          from: 'hardebaryorone.com',
          subject: 'Muses password Reset',
          text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
            'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
            'http://' + req.headers.host + '/reset/' + token + '\n\n' +
            'If you did not request this, please ignore this email and your password will remain unchanged.\n'
        };
        smtpTransport.sendMail(mailOptions, function(err) {
          req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
          done(err, 'done');
        });
      }
    ], function(err) {
      if (err) return next(err);
      res.redirect('/forgot');
    });
  };