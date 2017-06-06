-- MySQL Script generated by MySQL Workbench
-- ti  6. kesäkuuta 2017 08.54.28
-- Model: New Model    Version: 1.0
-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL';

-- -----------------------------------------------------
-- Schema MyDataAccount
-- -----------------------------------------------------
DROP SCHEMA IF EXISTS `MyDataAccount` ;

-- -----------------------------------------------------
-- Schema MyDataAccount
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `MyDataAccount` DEFAULT CHARACTER SET utf8 ;
USE `MyDataAccount` ;

-- -----------------------------------------------------
-- Table `MyDataAccount`.`Accounts`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `MyDataAccount`.`Accounts` ;

CREATE TABLE IF NOT EXISTS `MyDataAccount`.`Accounts` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `globalIdentifier` VARCHAR(255) NOT NULL,
  `activated` TINYINT(1) NOT NULL DEFAULT 0,
  `deleted` TINYINT(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `globalIdenttifyer_UNIQUE` (`globalIdentifier` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `MyDataAccount`.`AccountInfo`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `MyDataAccount`.`AccountInfo` ;

CREATE TABLE IF NOT EXISTS `MyDataAccount`.`AccountInfo` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `firstname` VARCHAR(255) NOT NULL,
  `lastname` VARCHAR(255) NOT NULL,
  `base64Avatar` BLOB NULL DEFAULT NULL,
  `deleted` TINYINT(1) NOT NULL DEFAULT 0,
  `Accounts_id` INT NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `fk_Particulars_Accounts1_idx` (`Accounts_id` ASC),
  CONSTRAINT `fk_AccountInfo_Accounts1`
    FOREIGN KEY (`Accounts_id`)
    REFERENCES `MyDataAccount`.`Accounts` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `MyDataAccount`.`ServiceLinkRecords`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `MyDataAccount`.`ServiceLinkRecords` ;

CREATE TABLE IF NOT EXISTS `MyDataAccount`.`ServiceLinkRecords` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `serviceLinkRecord` BLOB NOT NULL,
  `pop_key` BLOB NOT NULL,
  `Accounts_id` INT NOT NULL,
  `serviceLinkRecordId` VARCHAR(255) NOT NULL,
  `serviceId` VARCHAR(255) NOT NULL,
  `surrogateId` VARCHAR(255) NOT NULL,
  `operatorId` VARCHAR(255) NOT NULL,
  `deleted` TINYINT(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX `fk_ServiceLinkRecords_Accounts1_idx` (`Accounts_id` ASC),
  UNIQUE INDEX `serviceLinkRecordId_UNIQUE` (`serviceLinkRecordId` ASC),
  CONSTRAINT `fk_ServiceLinkRecords_Accounts1`
    FOREIGN KEY (`Accounts_id`)
    REFERENCES `MyDataAccount`.`Accounts` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `MyDataAccount`.`ConsentRecords`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `MyDataAccount`.`ConsentRecords` ;

CREATE TABLE IF NOT EXISTS `MyDataAccount`.`ConsentRecords` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `consentRecord` BLOB NOT NULL,
  `ServiceLinkRecords_id` INT NOT NULL,
  `surrogateId` VARCHAR(255) NOT NULL,
  `consentRecordId` VARCHAR(255) NOT NULL,
  `ResourceSetId` VARCHAR(255) NOT NULL,
  `serviceLinkRecordId` VARCHAR(255) NOT NULL,
  `subjectId` VARCHAR(255) NOT NULL,
  `role` VARCHAR(255) NOT NULL,
  `consentPairId` VARCHAR(255) NOT NULL,
  `deleted` TINYINT(1) NOT NULL DEFAULT 0,
  `Accounts_id` INT NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `fk_ConsentRecords_ServiceLinkRecords1_idx` (`ServiceLinkRecords_id` ASC),
  UNIQUE INDEX `consentRecordId_UNIQUE` (`consentRecordId` ASC),
  INDEX `fk_ConsentRecords_Accounts1_idx` (`Accounts_id` ASC),
  CONSTRAINT `fk_ConsentRecords_ServiceLinkRecords1`
    FOREIGN KEY (`ServiceLinkRecords_id`)
    REFERENCES `MyDataAccount`.`ServiceLinkRecords` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_ConsentRecords_Accounts1`
    FOREIGN KEY (`Accounts_id`)
    REFERENCES `MyDataAccount`.`Accounts` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `MyDataAccount`.`LocalIdentityPWDs`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `MyDataAccount`.`LocalIdentityPWDs` ;

CREATE TABLE IF NOT EXISTS `MyDataAccount`.`LocalIdentityPWDs` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `password` VARCHAR(255) NOT NULL,
  `deleted` TINYINT(1) NOT NULL DEFAULT 0,
  `Accounts_id` INT NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `fk_LocalIdentityPWDs_Accounts1_idx` (`Accounts_id` ASC),
  CONSTRAINT `fk_LocalIdentityPWDs_Accounts1`
    FOREIGN KEY (`Accounts_id`)
    REFERENCES `MyDataAccount`.`Accounts` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `MyDataAccount`.`LocalIdentities`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `MyDataAccount`.`LocalIdentities` ;

CREATE TABLE IF NOT EXISTS `MyDataAccount`.`LocalIdentities` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(255) NOT NULL,
  `LocalIdentityPWDs_id` INT NOT NULL,
  `Accounts_id` INT NOT NULL,
  `deleted` TINYINT(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `username_UNIQUE` (`username` ASC),
  INDEX `fk_LocalIdentities_LocalIdentityPWDs1_idx` (`LocalIdentityPWDs_id` ASC),
  INDEX `fk_LocalIdentities_Accounts1_idx` (`Accounts_id` ASC),
  CONSTRAINT `fk_LocalIdentities_LocalIdentityPWDs1`
    FOREIGN KEY (`LocalIdentityPWDs_id`)
    REFERENCES `MyDataAccount`.`LocalIdentityPWDs` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_LocalIdentities_Accounts1`
    FOREIGN KEY (`Accounts_id`)
    REFERENCES `MyDataAccount`.`Accounts` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `MyDataAccount`.`Salts`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `MyDataAccount`.`Salts` ;

CREATE TABLE IF NOT EXISTS `MyDataAccount`.`Salts` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `salt` VARCHAR(255) NOT NULL,
  `LocalIdentities_id` INT NOT NULL,
  `deleted` TINYINT(1) NOT NULL DEFAULT 0,
  `Accounts_id` INT NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `hash_UNIQUE` (`salt` ASC),
  INDEX `fk_Salts_LocalIdentities1_idx` (`LocalIdentities_id` ASC),
  INDEX `fk_Salts_Accounts1_idx` (`Accounts_id` ASC),
  CONSTRAINT `fk_Salts_LocalIdentities1`
    FOREIGN KEY (`LocalIdentities_id`)
    REFERENCES `MyDataAccount`.`LocalIdentities` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_Salts_Accounts1`
    FOREIGN KEY (`Accounts_id`)
    REFERENCES `MyDataAccount`.`Accounts` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `MyDataAccount`.`ConsentStatusRecords`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `MyDataAccount`.`ConsentStatusRecords` ;

CREATE TABLE IF NOT EXISTS `MyDataAccount`.`ConsentStatusRecords` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `consentStatusRecordId` VARCHAR(255) NOT NULL,
  `consentStatus` VARCHAR(255) NOT NULL,
  `consentStatusRecord` BLOB NOT NULL,
  `ConsentRecords_id` INT NOT NULL,
  `consentRecordId` VARCHAR(255) NOT NULL,
  `issued_at` BIGINT NOT NULL,
  `prevRecordId` VARCHAR(255) NOT NULL,
  `deleted` TINYINT(1) NOT NULL DEFAULT 0,
  `Accounts_id` INT NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `fk_ConsentStatusRecords_ConsentRecords1_idx` (`ConsentRecords_id` ASC),
  UNIQUE INDEX `consentStatusRecordId_UNIQUE` (`consentStatusRecordId` ASC),
  INDEX `fk_ConsentStatusRecords_Accounts1_idx` (`Accounts_id` ASC),
  CONSTRAINT `fk_ConsentStatusRecords_ConsentRecords1`
    FOREIGN KEY (`ConsentRecords_id`)
    REFERENCES `MyDataAccount`.`ConsentRecords` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_ConsentStatusRecords_Accounts1`
    FOREIGN KEY (`Accounts_id`)
    REFERENCES `MyDataAccount`.`Accounts` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `MyDataAccount`.`ServiceLinkStatusRecords`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `MyDataAccount`.`ServiceLinkStatusRecords` ;

CREATE TABLE IF NOT EXISTS `MyDataAccount`.`ServiceLinkStatusRecords` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `serviceLinkStatus` VARCHAR(255) NOT NULL,
  `serviceLinkStatusRecord` BLOB NOT NULL,
  `ServiceLinkRecords_id` INT NOT NULL,
  `serviceLinkRecordId` VARCHAR(255) NOT NULL,
  `issued_at` BIGINT NOT NULL,
  `prevRecordId` VARCHAR(255) NOT NULL,
  `serviceLinkStatusRecordId` VARCHAR(255) NOT NULL,
  `deleted` TINYINT(1) NOT NULL DEFAULT 0,
  `Accounts_id` INT NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `fk_ServiceLinkStatusRecords_ServiceLinkRecords1_idx` (`ServiceLinkRecords_id` ASC),
  UNIQUE INDEX `serviceLinkStatusRecordId_UNIQUE` (`serviceLinkStatusRecordId` ASC),
  INDEX `fk_ServiceLinkStatusRecords_Accounts1_idx` (`Accounts_id` ASC),
  CONSTRAINT `fk_ServiceLinkStatusRecords_ServiceLinkRecords1`
    FOREIGN KEY (`ServiceLinkRecords_id`)
    REFERENCES `MyDataAccount`.`ServiceLinkRecords` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_ServiceLinkStatusRecords_Accounts1`
    FOREIGN KEY (`Accounts_id`)
    REFERENCES `MyDataAccount`.`Accounts` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `MyDataAccount`.`EventLogs`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `MyDataAccount`.`EventLogs` ;

CREATE TABLE IF NOT EXISTS `MyDataAccount`.`EventLogs` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `event` BLOB NOT NULL,
  `Accounts_id` INT NOT NULL,
  `deleted` TINYINT(1) NOT NULL DEFAULT 0,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  INDEX `fk_EventLogs_Accounts1_idx` (`Accounts_id` ASC),
  CONSTRAINT `fk_EventLogs_Accounts1`
    FOREIGN KEY (`Accounts_id`)
    REFERENCES `MyDataAccount`.`Accounts` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;

-- begin attached script 'log_cleaner'
CREATE EVENT log_cleaner
    ON SCHEDULE AT CURRENT_TIMESTAMP + INTERVAL 1 DAY
    DO
	  DELETE FROM MyDataAccount.EventLogs WHERE created_at < (NOW() - INTERVAL 1 WEEK);
-- end attached script 'log_cleaner'
