-- MySQL Script generated by MySQL Workbench
-- to 15. syyskuuta 2016 15.32.11
-- Model: New Model    Version: 1.0
-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';

-- -----------------------------------------------------
-- Schema mydb
-- -----------------------------------------------------
-- -----------------------------------------------------
-- Schema db_Operator
-- -----------------------------------------------------

-- -----------------------------------------------------
-- Schema db_Operator
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `db_Operator` DEFAULT CHARACTER SET utf8 ;
USE `db_Operator` ;

-- -----------------------------------------------------
-- Table `db_Operator`.`cr_tbl`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `db_Operator`.`cr_tbl` ;

CREATE TABLE IF NOT EXISTS `db_Operator`.`cr_tbl` (
  `rs_id` LONGTEXT NOT NULL,
  `json` LONGTEXT NOT NULL,
  PRIMARY KEY (`rs_id`(255)))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `db_Operator`.`rs_id_tbl`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `db_Operator`.`rs_id_tbl` ;

CREATE TABLE IF NOT EXISTS `db_Operator`.`rs_id_tbl` (
  `rs_id` LONGTEXT NOT NULL,
  `used` TINYINT(1) NOT NULL,
  PRIMARY KEY (`rs_id`(255)))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `db_Operator`.`session_store`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `db_Operator`.`session_store` ;

CREATE TABLE IF NOT EXISTS `db_Operator`.`session_store` (
  `code` LONGTEXT NOT NULL,
  `json` LONGTEXT NOT NULL,
  PRIMARY KEY (`code`(255)))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;

CREATE USER 'operator'@'%' IDENTIFIED BY 'MynorcA';
GRANT CREATE TEMPORARY TABLES, DELETE, DROP, INSERT, LOCK TABLES, SELECT, UPDATE ON db_Operator.* TO 'operator'@'%';
FLUSH PRIVILEGES;