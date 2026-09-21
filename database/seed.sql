-- ==============================================================================
-- SEED.SQL: DETERMINISTIC TESTING DATASET
-- ==============================================================================
-- Purpose:
-- Provides a small, predictable, deterministic dataset strictly for
-- automated unit tests (pytest) and CI/CD verification.
--
-- DATASET STRATEGY:
-- 1. Unit & Integration Testing:
--    Use this file (seed.sql). It executes in milliseconds, contains known
--    controlled test records, and validates relational constraints, curated
--    views (ai_customer, ai_staff, ai_store_location), and late-fee calculations.
--
-- 2. Final Business Intelligence Agent Demo & Realistic Time-Series:
--    Use the full historical dataset located in:
--    `../sakila_extended_bundle/sakila-extended-data.sql`
--    (28,319 rentals, 33,914 payments, 63,419 customer events spanning May 2005
--    through May 2006).
-- ==============================================================================

USE sakila_extended;

SET FOREIGN_KEY_CHECKS = 0;

-- 1. Geographic Master Data
INSERT INTO country (country_id, country) VALUES 
(1, 'United States'),
(2, 'Canada'),
(3, 'United Kingdom'),
(4, 'Vietnam'),
(5, 'Japan');

INSERT INTO city (city_id, city, country_id) VALUES 
(1, 'Seattle', 1),
(2, 'Vancouver', 2),
(3, 'London', 3),
(4, 'Ho Chi Minh City', 4),
(5, 'Tokyo', 5);

INSERT INTO address (address_id, address, district, city_id, postal_code, phone, location) VALUES 
(1, '47 MySakila Drive', 'Alberta', 1, '98101', '14033335568', ST_GeomFromText('POINT(0 0)', 0)),
(2, '28 MySQL Boulevard', 'QLD', 2, 'V6B 2W9', '6172235589', ST_GeomFromText('POINT(0 0)', 0)),
(3, '1913 Nguyen Hue', 'District 1', 4, '70000', '84901234567', ST_GeomFromText('POINT(0 0)', 0)),
(4, '1121 Loja Avenue', 'California', 1, '90210', '1952223065', ST_GeomFromText('POINT(0 0)', 0)),
(5, '403 Central Perk St', 'Tokyo-to', 5, '100-0001', '81312345678', ST_GeomFromText('POINT(0 0)', 0));

-- 2. Staff and Store (with store-staff consistency enforced)
INSERT INTO staff (staff_id, first_name, last_name, address_id, email, store_id, active, username, password) VALUES 
(1, 'Mike', 'Hillyer', 1, 'Mike.Hillyer@sakilastaff.com', 1, 1, 'Mike', '8cb2237d0679ca88db6464eac60da96345513964'),
(2, 'Jon', 'Stephens', 2, 'Jon.Stephens@sakilastaff.com', 2, 1, 'Jon', '8cb2237d0679ca88db6464eac60da96345513964');

INSERT INTO store (store_id, manager_staff_id, address_id) VALUES 
(1, 1, 1),
(2, 2, 2);

-- 3. Categories & Languages
INSERT INTO category (category_id, name) VALUES 
(1, 'Action'),
(2, 'Animation'),
(3, 'Children'),
(4, 'Classics'),
(5, 'Comedy'),
(6, 'Drama'),
(7, 'Sci-Fi'),
(8, 'Sports');

INSERT INTO language (language_id, name) VALUES 
(1, 'English'),
(2, 'Italian'),
(3, 'Japanese'),
(4, 'French');

-- 4. Films
INSERT INTO film (film_id, title, description, release_year, language_id, rental_duration, rental_rate, length, replacement_cost, rating) VALUES 
(1, 'ACADEMY DINOSAUR', 'An Epic Drama of a Feminist and a Mad Scientist who must Battle a Teacher in The Canadian Rockies', 2006, 1, 6, 0.99, 86, 20.99, 'PG'),
(2, 'ACE GOLDFINGER', 'An Astounding Epistle of a Database Administrator and an Explorer who must Explore a Car in Ancient China', 2006, 1, 3, 4.99, 48, 12.99, 'G'),
(3, 'ADAPTATION HOLES', 'An Astounding Reflection of a Lumberjack and a Car who must Sink a Lumberjack in A Baloon', 2006, 1, 7, 2.99, 50, 18.99, 'NC-17'),
(4, 'AFFAIR PREJUDICE', 'A Fanciful Documentary of a Frisbee and a Lumberjack who must Chase a Monkey in A Shark Tank', 2006, 1, 5, 2.99, 117, 26.99, 'G'),
(5, 'AFRICAN EGG', 'A Fast-Paced Documentary of a Pastry Chef and a Dentist who must Pursue a Forensic Psychologist in The Gulf of Mexico', 2006, 1, 6, 2.99, 130, 22.99, 'G');

INSERT INTO film_category (film_id, category_id) VALUES 
(1, 6), -- Drama
(2, 1), -- Action
(3, 7), -- Sci-Fi
(4, 4), -- Classics
(5, 5); -- Comedy

-- 5. Inventory (Populated with analytical acquisition_cost)
INSERT INTO inventory (inventory_id, film_id, store_id, acquisition_cost) VALUES 
(1, 1, 1, 11.45),
(2, 1, 1, 11.20),
(3, 1, 2, 11.50),
(4, 2, 1, 7.20),
(5, 2, 2, 7.35),
(6, 3, 1, 9.80),
(7, 3, 2, 9.65),
(8, 4, 1, 14.20),
(9, 5, 2, 12.10);

-- 6. Customers
INSERT INTO customer (customer_id, store_id, first_name, last_name, email, address_id, active, create_date) VALUES 
(1, 1, 'MARY', 'SMITH', 'MARY.SMITH@sakilacustomer.org', 3, 1, '2005-05-25 11:30:37'),
(2, 1, 'PATRICIA', 'JOHNSON', 'PATRICIA.JOHNSON@sakilacustomer.org', 4, 1, '2005-05-25 11:30:37'),
(3, 2, 'LINDA', 'WILLIAMS', 'LINDA.WILLIAMS@sakilacustomer.org', 5, 1, '2005-05-25 11:30:37');

-- 7. Rentals & Payments (Controlled test scenarios)
-- Scenario A: Returned on-time (no late fee)
INSERT INTO rental (rental_id, rental_date, inventory_id, customer_id, return_date, staff_id) VALUES 
(1, '2005-06-01 10:00:00', 1, 1, '2005-06-05 12:00:00', 1);
INSERT INTO payment (payment_id, customer_id, staff_id, rental_id, amount, payment_date) VALUES 
(1, 1, 1, 1, 0.99, '2005-06-01 10:00:00');

-- Scenario B: Returned late (rental duration 3 days, returned after 8 days -> 5 days late fee $5.00)
INSERT INTO rental (rental_id, rental_date, inventory_id, customer_id, return_date, staff_id) VALUES 
(2, '2005-06-02 14:30:00', 4, 2, '2005-06-10 16:00:00', 1);
INSERT INTO payment (payment_id, customer_id, staff_id, rental_id, amount, payment_date) VALUES 
(2, 2, 1, 2, 4.99, '2005-06-02 14:30:00'),
(3, 2, 1, 2, 5.00, '2005-06-10 16:00:00'); -- Late fee payment

-- Scenario C: Active open rental
INSERT INTO rental (rental_id, rental_date, inventory_id, customer_id, return_date, staff_id) VALUES 
(3, '2005-06-12 09:15:00', 6, 3, NULL, 2);
INSERT INTO payment (payment_id, customer_id, staff_id, rental_id, amount, payment_date) VALUES 
(4, 3, 2, 3, 2.99, '2005-06-12 09:15:00');

-- 8. Customer Events (Funnel analysis test data)
INSERT INTO customer_event (event_id, customer_id, event_time, store_id, film_id, event_type, available_flag) VALUES 
(1, 1, '2005-06-01 09:45:00', 1, 1, 'BROWSE', 1),
(2, 1, '2005-06-01 09:50:00', 1, 1, 'AVAILABILITY_CHECK', 1),
(3, 1, '2005-06-01 10:00:00', 1, 1, 'RENTAL', 1),
(4, 1, '2005-06-05 12:00:00', 1, 1, 'RETURN', 1),
(5, 2, '2005-06-02 14:15:00', 1, 2, 'AVAILABILITY_CHECK', 1),
(6, 2, '2005-06-02 14:30:00', 1, 2, 'RENTAL', 1),
(7, 2, '2005-06-10 16:00:00', 1, 2, 'RETURN', 1),
(8, 3, '2005-06-12 09:00:00', 2, 3, 'BROWSE', 1),
(9, 3, '2005-06-12 09:15:00', 2, 3, 'RENTAL', 1);

SET FOREIGN_KEY_CHECKS = 1;

-- ------------------------------------------------------------------------------
-- Seed initial record for agent_system (verifies foreign keys & state schema)
-- ------------------------------------------------------------------------------
USE agent_system;

INSERT INTO chat_sessions (session_id, title) VALUES 
('default_session', 'Initial System Test Session');

-- ==============================================================================
-- POST-SEED VERIFICATION (Run in MySQL Workbench to confirm seed integrity)
-- Expected counts:
--   address        = 5
--   store          = 2
--   staff          = 2
--   customer       = 3
--   rental         = 3
--   payment        = 4
--   customer_event = 9
-- ==============================================================================
USE sakila_extended;
SELECT 'address' AS table_name, COUNT(*) AS row_count FROM address
UNION ALL
SELECT 'store' AS table_name, COUNT(*) AS row_count FROM store
UNION ALL
SELECT 'staff' AS table_name, COUNT(*) AS row_count FROM staff
UNION ALL
SELECT 'customer' AS table_name, COUNT(*) AS row_count FROM customer
UNION ALL
SELECT 'rental' AS table_name, COUNT(*) AS row_count FROM rental
UNION ALL
SELECT 'payment' AS table_name, COUNT(*) AS row_count FROM payment
UNION ALL
SELECT 'customer_event' AS table_name, COUNT(*) AS row_count FROM customer_event;

