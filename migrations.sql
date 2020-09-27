ALTER TABLE `users` ADD `name` VARCHAR(254) NOT NULL AFTER `username`;
ALTER TABLE `characters` ADD `id_card` VARCHAR(254) NOT NULL AFTER `birthday`;
ALTER TABLE `characters` ADD `comment` VARCHAR(254) NOT NULL AFTER `b`,  
ALTER TABLE `characters` ADD `last_edited` VARCHAR(254) NOT NULL AFTER `comment`;
ALTER TABLE `characters` ADD `last_edited_from` INT(11) NOT NULL AFTER `last_edited`;