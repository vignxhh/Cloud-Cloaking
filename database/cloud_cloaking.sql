-- phpMyAdmin SQL Dump
-- version 2.11.6
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Jan 27, 2024 at 07:25 AM
-- Server version: 5.0.51
-- PHP Version: 5.2.6

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `cloud_cloaking`
--

-- --------------------------------------------------------

--
-- Table structure for table `admin_login`
--

CREATE TABLE `admin_login` (
  `username` varchar(20) NOT NULL,
  `password` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `admin_login`
--

INSERT INTO `admin_login` (`username`, `password`) VALUES
('admin', 'admin');

-- --------------------------------------------------------

--
-- Table structure for table `data_files`
--

CREATE TABLE `data_files` (
  `id` int(11) NOT NULL,
  `owner_id` varchar(20) NOT NULL,
  `description` varchar(100) NOT NULL,
  `file_name` varchar(50) NOT NULL,
  `file_type` varchar(100) NOT NULL,
  `file_size` double NOT NULL,
  `reg_date` varchar(20) NOT NULL,
  `reg_time` varchar(20) NOT NULL,
  `file_extension` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `data_files`
--

INSERT INTO `data_files` (`id`, `owner_id`, `description`, `file_name`, `file_type`, `file_size`, `reg_date`, `reg_time`, `file_extension`) VALUES
(1, 'james', 'my image', 'F1cld1.png', 'image/png', 106.91, '11-12-2023', '16:35', 'img_png.jpg'),
(2, 'james', 'data', 'F2data.txt', 'text/plain', 0.73, '11-12-2023', '16:36', 'img_txt.jpg'),
(3, 'james', 'my document', 'F3cloud-cloaking1.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 1284.2, '11-12-2023', '16:57', 'img_doc.jpg'),
(4, 'james', 'my data', 'F4dataneg.csv', 'text/csv', 1847.73, '11-12-2023', '17:09', 'img_csv.jpg'),
(5, 'james', 'my document', 'F5datapos.csv', 'text/csv', 1219.28, '11-12-2023', '17:21', 'img_csv.jpg'),
(6, 'james', 'my data', 'F6aa.txt', 'text/plain', 0.27, '23-12-2023', '12:02', 'img_txt.jpg'),
(7, 'james', 'my image', 'F7mm.png', 'image/png', 864.56, '23-12-2023', '12:09', 'img_png.jpg');

-- --------------------------------------------------------

--
-- Table structure for table `data_owner`
--

CREATE TABLE `data_owner` (
  `id` int(11) NOT NULL,
  `name` varchar(20) NOT NULL,
  `mobile` bigint(20) NOT NULL,
  `email` varchar(40) NOT NULL,
  `city` varchar(30) NOT NULL,
  `owner_id` varchar(20) NOT NULL,
  `password` varchar(20) NOT NULL,
  `reg_date` varchar(20) NOT NULL,
  `status` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `data_owner`
--

INSERT INTO `data_owner` (`id`, `name`, `mobile`, `email`, `city`, `owner_id`, `password`, `reg_date`, `status`) VALUES
(1, 'James', 9845126577, 'james@gmail.com', 'Madurai', 'james', '123456', '07-12-2023', 1);

-- --------------------------------------------------------

--
-- Table structure for table `data_share`
--

CREATE TABLE `data_share` (
  `id` int(11) NOT NULL,
  `owner_id` varchar(20) NOT NULL,
  `fid` int(11) NOT NULL,
  `username` varchar(20) NOT NULL,
  `share_type` int(11) NOT NULL,
  `share_date` varchar(20) NOT NULL,
  `sdate` varchar(20) NOT NULL,
  `edate` varchar(20) NOT NULL,
  `stime` varchar(20) NOT NULL,
  `etime` varchar(20) NOT NULL,
  `days` varchar(30) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `data_share`
--

INSERT INTO `data_share` (`id`, `owner_id`, `fid`, `username`, `share_type`, `share_date`, `sdate`, `edate`, `stime`, `etime`, `days`) VALUES
(1, 'james', 1, 'ramesh', 1, '11-12-2023', '', '', '', '', ''),
(2, 'james', 2, 'ramesh', 2, '11-12-2023', '', '', '', '', ''),
(3, 'james', 3, 'ramesh', 3, '11-12-2023', '11-12-2023', '12-12-2023', '10:30', '20:30', '1,2,3,4,5,6,7'),
(4, 'james', 7, 'ramesh', 3, '23-12-2023', '23-12-2023', '23-12-2023', '12:5', '15:30', '1,2,3,4,5,6,7');

-- --------------------------------------------------------

--
-- Table structure for table `data_user`
--

CREATE TABLE `data_user` (
  `id` int(11) NOT NULL,
  `name` varchar(20) NOT NULL,
  `owner_id` varchar(20) NOT NULL,
  `gender` varchar(10) NOT NULL,
  `dob` varchar(20) NOT NULL,
  `mobile` bigint(20) NOT NULL,
  `email` varchar(40) NOT NULL,
  `location` varchar(30) NOT NULL,
  `designation` varchar(30) NOT NULL,
  `username` varchar(20) NOT NULL,
  `password` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `data_user`
--

INSERT INTO `data_user` (`id`, `name`, `owner_id`, `gender`, `dob`, `mobile`, `email`, `location`, `designation`, `username`, `password`) VALUES
(1, 'Ramesh', 'james', 'Male', '05-06-1998', 9854125487, 'bgeduscanner@gmail.com', 'Chennai', 'Developer', 'ramesh', '123456');

-- --------------------------------------------------------

--
-- Table structure for table `geo_location`
--

CREATE TABLE `geo_location` (
  `id` int(11) NOT NULL,
  `location` varchar(30) NOT NULL,
  `detail` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `geo_location`
--

INSERT INTO `geo_location` (`id`, `location`, `detail`) VALUES
(1, 'Head office', 'new google.maps.LatLng(10.886908,78.691389), new google.maps.LatLng(10.849145,78.728468), new google.maps.LatLng(10.825541,78.688299), new google.maps.LatLng(10.862632,78.643324), '),
(2, 'Chennai', 'new google.maps.LatLng(10.88758,78.63543), new google.maps.LatLng(10.84982,78.67251), new google.maps.LatLng(10.82622,78.63234), new google.maps.LatLng(10.86331,78.58736), '),
(3, 'branch2', 'new google.maps.LatLng(11.025521,78.378452), new google.maps.LatLng(10.976317,78.447803), new google.maps.LatLng(10.969913,78.360599), new google.maps.LatLng(11.025521,78.378452), ');

-- --------------------------------------------------------

--
-- Table structure for table `share_location`
--

CREATE TABLE `share_location` (
  `id` int(11) NOT NULL,
  `username` varchar(20) NOT NULL,
  `share_type` int(11) NOT NULL,
  `share_id` int(11) NOT NULL,
  `location_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `share_location`
--

INSERT INTO `share_location` (`id`, `username`, `share_type`, `share_id`, `location_id`) VALUES
(1, 'ramesh', 2, 2, 3),
(2, 'ramesh', 2, 2, 3);
