ALTER TABLE `users` ADD `name` VARCHAR(254) NOT NULL AFTER `username`;
ALTER TABLE `characters` ADD `id_card` VARCHAR(254) NOT NULL AFTER `birthday`;
ALTER TABLE `characters` ADD `comment` VARCHAR(254) NOT NULL AFTER `b`,  
ALTER TABLE `characters` ADD `last_edited` VARCHAR(254) NOT NULL AFTER `comment`;
ALTER TABLE `characters` ADD `last_edited_from` INT(11) NOT NULL AFTER `last_edited`;
ALTER TABLE `characters` ADD `medic_assessment` VARCHAR(254) NOT NULL AFTER `last_edited_from`;
ALTER TABLE `characters` ADD `medic_assessment_edited` VARCHAR(254) NOT NULL AFTER `medic_assessment`;
ALTER TABLE `characters` ADD `medic_assessment_edited_from` VARCHAR(254) NOT NULL AFTER `medic_assessment_edited`;
