const {DataTypes} = require('sequelize');
const crypto = require('crypto');
const moment = require('moment-timezone');
const sequelize = require('../../config/sequelize');

/**
 * Refresh Token Model
 */
const RefreshToken = sequelize.define('refresh_token', {
  token: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    primaryKey: true,
  },
  id_user: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'User',
      key: 'id_user',
    },
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    references: {
      model: 'User',
      key: 'email',
    },
  },
  expires: {
    type: DataTypes.DATE,
    allowNull: false,
  },
}, { freezeTableName: true, autoIncrement: false, id: false });

RefreshToken.generate = async function (user) {
  // eslint-disable-next-line camelcase
  const { id_user, email } = user;
  // eslint-disable-next-line camelcase
  const token = `${id_user}.${crypto.randomBytes(40).toString('hex')}`;
  const expires = moment().add(30, 'days').toDate();
  // eslint-disable-next-line no-return-await
  try {
    return await RefreshToken.create({
      token,
      id_user,
      email,
      expires,
    });
  } catch (error) {
    console.log(error);
    return error;
  }
};

module.exports = RefreshToken;
