const Sequelize = require('sequelize');
const httpStatus = require('http-status');
const { omitBy, isNil } = require('lodash');
const bcrypt = require('bcryptjs');
const moment = require('moment-timezone');
const jwt = require('jwt-simple');
const uuidv4 = require('uuid/v4');
const sequelize = require('../../config/sequelize');
const APIError = require('../errors/api-error');
const { jwtSecret, jwtExpirationInterval } = require('../../config/vars');

const userSchema = sequelize.define('user', {
  id_user: {
    type: Sequelize.INTEGER,
    autoIncrement: true,
    allowNull: false,
    primaryKey: true,
  },
  email: {
    type: Sequelize.CHAR(100),
    allowNull: false,
    unique: true,
  },
  password: {
    type: Sequelize.CHAR(100),
    allowNull: false,
  },
  name: {
    type: Sequelize.CHAR(100),
    allowNull: false,
  },
  role: {
    type: Sequelize.CHAR(100),
  },
  picture: {
    type: Sequelize.CHAR(100),
  },
}, {
  timestamps: true,
  autoIncrement: false,
  id: false,
});

// eslint-disable-next-line func-names,no-use-before-define
userSchema.roles = function () {
  return ['user', 'admin'];
};

userSchema.beforeSave((user) => {
  if (user.changed('password')) {
    const salt = bcrypt.genSaltSync(10);
    // eslint-disable-next-line no-param-reassign
    user.password = bcrypt.hashSync(user.password, salt);
  }
});

userSchema.beforeUpdate(async (user) => {
  if (user.changed('password')) {
    const salt = bcrypt.genSaltSync(10);
    // eslint-disable-next-line no-param-reassign
    user.password = bcrypt.hashSync(user.password, salt);
  }
});

// eslint-disable-next-line func-names
userSchema.prototype.transform = function () {
  const transformed = {};
  const fields = ['id', 'name', 'email', 'picture', 'role', 'createdAt'];

  fields.forEach((field) => {
    transformed[field] = this[field];
  });

  return transformed;
};

// eslint-disable-next-line no-unused-expressions,func-names
userSchema.prototype.token = function () {
  const payload = {
    exp: moment().add(jwtExpirationInterval, 'minutes').unix(),
    iat: moment().unix(),
    sub: this.id_user,
  };
  return jwt.encode(payload, jwtSecret);
};

// eslint-disable-next-line func-names
userSchema.prototype.passwordMatches = function (password) {
  return bcrypt.compare(password, this.password);
};

// eslint-disable-next-line func-names
userSchema.roles = function () {
  return ['user', 'admin'];
};

// eslint-disable-next-line no-unused-expressions,func-names
userSchema.get = async function (id) {
  let ret;
  // eslint-disable-next-line prefer-const
  ret = await this.findByPk(id);
  if (ret) {
    return ret;
  }

  throw new APIError({
    message: 'User does not exist',
    status: httpStatus.NOT_FOUND,
  });
};

// eslint-disable-next-line no-unused-expressions,func-names
userSchema.findAndGenerateToken = async function (options) {
  const { email, password, refreshObject } = options;
  if (!email) throw new APIError({ message: 'An email is required to generate a token' });

  const user = await this.findOne({ email });
  const err = {
    status: httpStatus.UNAUTHORIZED,
    isPublic: true,
  };
  if (password) {
    if (user && await user.passwordMatches(password)) {
      return { user, accessToken: user.token() };
    }
    err.message = 'Incorrect email or password';
  } else if (refreshObject && refreshObject.userEmail === email) {
    if (moment(refreshObject.expires).isBefore()) {
      err.message = 'Invalid refresh token.';
    } else {
      return { user, accessToken: user.token() };
    }
  } else {
    err.message = 'Incorrect email or refreshToken';
  }
  throw new APIError(err);
};

// eslint-disable-next-line func-names,no-unused-expressions
userSchema.list = async function ({
                                    page = 1, perPage = 30, name, email, role,
                                  }) {
  const options = omitBy({ name, email, role }, isNil);

  const { count, rows } = await this.findAndCountAll({
    where: options,
    order: [['createdAt', 'DESC']],
    offset: perPage * (page - 1),
    limit: perPage,
  });

  return {
    total: count,
    results: rows,
  };
};

// eslint-disable-next-line func-names,no-unused-expressions
userSchema.checkDuplicateEmail = function (error) {
  if (error.name === 'SequelizeUniqueConstraintError') {
    return new APIError({
      message: 'Validation Error',
      errors: [{
        field: 'email',
        location: 'body',
        messages: ['"email" already exists'],
      }],
      status: httpStatus.CONFLICT,
      isPublic: true,
      stack: error.stack,
    });
  }
  return error;
};

// eslint-disable-next-line no-unused-expressions,func-names
userSchema.oAuthLogin = async function ({
                                          service, id, email, name, picture,
                                        }) {
  const user = await this.findOne({ $or: [{ [`services.${service}`]: id }, { email }] });
  if (user) {
    user.services[service] = id;
    if (!user.name) user.name = name;
    if (!user.picture) user.picture = picture;
    return user.save();
  }
  const password = uuidv4();
  return this.create({
    services: { [service]: id }, email, password, name, picture,
  });
};

module.exports = userSchema;
