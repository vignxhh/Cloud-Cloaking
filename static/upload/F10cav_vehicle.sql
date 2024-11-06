-- phpMyAdmin SQL Dump
-- version 2.11.6
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Mar 19, 2024 at 05:25 AM
-- Server version: 5.0.51
-- PHP Version: 5.2.6

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `cav_vehicle`
--

-- --------------------------------------------------------

--
-- Table structure for table `cav_admin`
--

CREATE TABLE `cav_admin` (
  `username` varchar(20) NOT NULL,
  `password` varchar(20) NOT NULL,
  `utype` varchar(20) NOT NULL,
  `bcode` varchar(20) NOT NULL,
  `url_link` varchar(100) NOT NULL,
  `uname2` varchar(20) NOT NULL,
  `pass2` varchar(20) NOT NULL,
  `block_count` int(11) NOT NULL,
  `pre_value` varchar(100) NOT NULL,
  PRIMARY KEY  (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `cav_admin`
--


-- --------------------------------------------------------

--
-- Table structure for table `traffic_data`
--

CREATE TABLE `traffic_data` (
  `id` int(11) NOT NULL,
  `signal1` int(11) NOT NULL,
  `signal2` int(11) NOT NULL,
  `signal3` int(11) NOT NULL,
  `signal4` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `traffic_data`
--

INSERT INTO `traffic_data` (`id`, `signal1`, `signal2`, `signal3`, `signal4`) VALUES
(1, 3, 2, 1, 4),
(2, 1, 2, 3, 3),
(3, 2, 5, 4, 1),
(4, 1, 2, 4, 8),
(5, 5, 3, 1, 4),
(6, 1, 2, 2, 3),
(7, 1, 2, 3, 4),
(8, 1, 2, 3, 3),
(9, 1, 2, 4, 3),
(10, 3, 8, 6, 2),
(11, 8, 9, 7, 11),
(12, 4, 5, 3, 1),
(13, 1, 3, 4, 2),
(14, 3, 8, 1, 11),
(15, 1, 3, 2, 1),
(16, 2, 1, 3, 5),
(17, 3, 2, 1, 2),
(18, 6, 9, 2, 3),
(19, 7, 1, 3, 4),
(20, 5, 2, 4, 6);
