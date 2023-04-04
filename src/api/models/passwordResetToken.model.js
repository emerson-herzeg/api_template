const Sequelize = require('sequelize');
const crypto = require('crypto');
const moment = require('moment-timezone');
const sequelize = require('../../config/sequelize');

const PasswordResetToken = sequelize.define('password_reset_token', {
  resetToken: {
    type: Sequelize.STRING,
    allowNull: false,
    unique: true,
    primaryKey: true,
  },
  id_user: {
    type: Sequelize.INTEGER,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id_user',
    },
  },
  email: {
    type: Sequelize.CHAR(100),
    allowNull: false,
    references: {
      model: 'users',
      key: 'email',
    },
  },
  expires: {
    type: Sequelize.DATE,
    allowNull: false,
  },
}, { freezeTableName: true, autoIncrement: false, id: false });

// eslint-disable-next-line func-names
PasswordResetToken.generate = async function (user) {
  // eslint-disable-next-line camelcase
  const { id_user } = user;
  const { email } = user;
  // eslint-disable-next-line camelcase
  const resetToken = `${id_user}.${crypto.randomBytes(40).toString('hex')}`;
  const expires = moment().add(2, 'hours').toDate();
  return PasswordResetToken.create({
    resetToken,
    id_user,
    email,
    expires,
  });
};

module.exports = PasswordResetToken;
