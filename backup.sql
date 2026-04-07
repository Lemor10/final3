--
-- PostgreSQL database dump
--

\restrict vYj2FvwDyKPn0lLNgKk5E188NhSD1bvFuEfwAg8as16R2aQBhx44LNofVwX8Wsp

-- Dumped from database version 18.3 (Debian 18.3-1.pgdg12+1)
-- Dumped by pg_dump version 18.3

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: final4_q7lh_user
--

-- *not* creating schema, since initdb creates it


ALTER SCHEMA public OWNER TO final4_q7lh_user;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: final4_q7lh_user
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


ALTER TABLE public.alembic_version OWNER TO final4_q7lh_user;

--
-- Name: dog; Type: TABLE; Schema: public; Owner: final4_q7lh_user
--

CREATE TABLE public.dog (
    id integer NOT NULL,
    uuid character varying(36) NOT NULL,
    is_archived boolean,
    deleted_reason character varying(100),
    deleted_cause character varying(150),
    deleted_at timestamp without time zone,
    deleted_by_owner_id integer,
    archived_at timestamp without time zone,
    name character varying(120) NOT NULL,
    breed character varying(120),
    birthdate date,
    gender character varying(10),
    owner_name character varying(150),
    owner_id integer,
    qr_code character varying(200),
    vaccinated character varying(50) NOT NULL,
    image character varying(200),
    last_vaccination date,
    next_vaccination date,
    vaccination_expiry date,
    vaccination_barangay character varying(100),
    vaccination_municipality character varying(100),
    vaccination_province character varying(100),
    vaccination_location character varying(100),
    created_at timestamp without time zone,
    registered_by_admin character varying(100),
    admin_archive_reason character varying(255),
    admin_archive_cause character varying(255),
    owner_barangay character varying(120),
    owner_municipality character varying(120),
    owner_province character varying(120),
    owner_email character varying(150),
    owner_mobile character varying(20),
    is_stray boolean,
    location_found character varying(255),
    vaccination_type character varying(100)
);


ALTER TABLE public.dog OWNER TO final4_q7lh_user;

--
-- Name: dog_id_seq; Type: SEQUENCE; Schema: public; Owner: final4_q7lh_user
--

CREATE SEQUENCE public.dog_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.dog_id_seq OWNER TO final4_q7lh_user;

--
-- Name: dog_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: final4_q7lh_user
--

ALTER SEQUENCE public.dog_id_seq OWNED BY public.dog.id;


--
-- Name: notifications; Type: TABLE; Schema: public; Owner: final4_q7lh_user
--

CREATE TABLE public.notifications (
    id integer NOT NULL,
    user_id integer NOT NULL,
    dog_id integer,
    title character varying(150) NOT NULL,
    message text NOT NULL,
    type character varying(50) NOT NULL,
    milestone character varying(20),
    due_date date,
    is_read boolean,
    dismissed boolean,
    email_sent boolean,
    created_at timestamp without time zone
);


ALTER TABLE public.notifications OWNER TO final4_q7lh_user;

--
-- Name: notifications_id_seq; Type: SEQUENCE; Schema: public; Owner: final4_q7lh_user
--

CREATE SEQUENCE public.notifications_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.notifications_id_seq OWNER TO final4_q7lh_user;

--
-- Name: notifications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: final4_q7lh_user
--

ALTER SEQUENCE public.notifications_id_seq OWNED BY public.notifications.id;


--
-- Name: user; Type: TABLE; Schema: public; Owner: final4_q7lh_user
--

CREATE TABLE public."user" (
    id integer NOT NULL,
    username character varying(50) NOT NULL,
    email character varying(150),
    email_verified boolean,
    verification_token character varying(200),
    last_notification_run date,
    name character varying(150),
    contact character varying(20),
    barangay character varying(100),
    municipality character varying(100),
    province character varying(100),
    address character varying(255),
    profile_photo character varying(200),
    password_hash character varying(200),
    role character varying(20),
    created_at timestamp without time zone,
    is_archived boolean,
    archived_at timestamp without time zone
);


ALTER TABLE public."user" OWNER TO final4_q7lh_user;

--
-- Name: user_id_seq; Type: SEQUENCE; Schema: public; Owner: final4_q7lh_user
--

CREATE SEQUENCE public.user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.user_id_seq OWNER TO final4_q7lh_user;

--
-- Name: user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: final4_q7lh_user
--

ALTER SEQUENCE public.user_id_seq OWNED BY public."user".id;


--
-- Name: dog id; Type: DEFAULT; Schema: public; Owner: final4_q7lh_user
--

ALTER TABLE ONLY public.dog ALTER COLUMN id SET DEFAULT nextval('public.dog_id_seq'::regclass);


--
-- Name: notifications id; Type: DEFAULT; Schema: public; Owner: final4_q7lh_user
--

ALTER TABLE ONLY public.notifications ALTER COLUMN id SET DEFAULT nextval('public.notifications_id_seq'::regclass);


--
-- Name: user id; Type: DEFAULT; Schema: public; Owner: final4_q7lh_user
--

ALTER TABLE ONLY public."user" ALTER COLUMN id SET DEFAULT nextval('public.user_id_seq'::regclass);


--
-- Data for Name: alembic_version; Type: TABLE DATA; Schema: public; Owner: final4_q7lh_user
--

COPY public.alembic_version (version_num) FROM stdin;
d1f1b05a06e9
\.


--
-- Data for Name: dog; Type: TABLE DATA; Schema: public; Owner: final4_q7lh_user
--

COPY public.dog (id, uuid, is_archived, deleted_reason, deleted_cause, deleted_at, deleted_by_owner_id, archived_at, name, breed, birthdate, gender, owner_name, owner_id, qr_code, vaccinated, image, last_vaccination, next_vaccination, vaccination_expiry, vaccination_barangay, vaccination_municipality, vaccination_province, vaccination_location, created_at, registered_by_admin, admin_archive_reason, admin_archive_cause, owner_barangay, owner_municipality, owner_province, owner_email, owner_mobile, is_stray, location_found, vaccination_type) FROM stdin;
26	93fa0d07-da76-422d-b5fe-95a58b44a758	t	Other	\N	2026-03-19 16:14:34.104809	74	2026-03-19 16:14:34.104816	Habibi	Chihuahua	2021-05-28	Female	Raffie P. David	74	93fa0d07-da76-422d-b5fe-95a58b44a758.png	Vaccinated	FB_IMG_1724356564777_edit_30419689827196.jpg	2025-11-11	2026-11-11	2028-11-11	Mabilo 	New Washington 	Aklan 	In house	2026-03-08 09:17:46.36653	\N	\N	\N	Mabilo	New Washington	Aklan	\N	\N	\N	\N	\N
61	1b2b3c6b-f091-436c-aa4f-02b518f0a71e	f	\N	\N	\N	\N	\N	Habibi	Chihuahua	2021-05-28	Female	Raffie P. David	74	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773936829/qr_codes/1b2b3c6b-f091-436c-aa4f-02b518f0a71e.png	Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773936828/dog_images/ypvmvepwp54chyuteqnq.jpg	2025-11-11	2026-11-11	2028-11-11	Mabilo	New Washington	Aklan	In-House	2026-03-19 16:13:49.935532	\N	\N	\N	Mabilo	New Washington	Aklan	\N	\N	f	\N	Anti-rabies
60	9e0a4404-5727-480f-87ec-d8637af3f458	f	\N	\N	\N	\N	\N	Jizu	Aspin	2020-01-15	Male	Kyle Trinidad	75	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773936373/qr_codes/9e0a4404-5727-480f-87ec-d8637af3f458.png	Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773936372/dog_images/llxrcmglpapxnqbm2tk5.jpg	2025-11-11	2026-11-11	2028-11-11	Mabilo	New Washington	Aklan	In-House	2026-03-19 16:06:13.954812	\N	\N	\N	Mabilo	New Washington	Aklan	\N	\N	f	\N	Anti-rabies
66	092bda7b-1ffc-4455-8218-ba271e56feca	f	\N	\N	\N	\N	\N	Stray1	Aspin	\N	Male	\N	\N	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774281019/qr_codes/092bda7b-1ffc-4455-8218-ba271e56feca.png	Not Vaccinated	\N	\N	\N	\N	\N	\N	\N	\N	2026-03-23 15:50:20.500864	\N	\N	\N	\N	\N	\N	\N	\N	t	Sector 6 Brgy. Mabilo New Washington Aklan	\N
67	73e50460-dd1d-439f-85b7-2eff32345994	f	\N	\N	\N	\N	\N	Stray2	Aspin	\N	Male	\N	\N	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774281045/qr_codes/73e50460-dd1d-439f-85b7-2eff32345994.png	Vaccinated	\N	2026-03-23	2026-03-30	2029-03-23	\N	\N	\N	\N	2026-03-23 15:50:45.782192	\N	\N	\N	\N	\N	\N	\N	\N	t	Sector 6 Brgy. Mabilo New Washington Aklan	Anti-rabies
70	e54e7007-7b5b-4487-b0df-336b46d61ca0	f	\N	\N	\N	\N	\N	Brownie	N/A	2025-08-30	Male	Jerson Aranas, Perez	96	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774946560/qr_codes/e54e7007-7b5b-4487-b0df-336b46d61ca0.png	Not Vaccinated	\N	\N	\N	\N	\N	\N	\N	\N	2026-03-31 08:42:42.035317	\N	\N	\N	Poblacion 	Kalibo	Aklan	\N	\N	f	\N	\N
28	90702630-6676-4c22-ab09-143931f22ab2	f	\N	\N	\N	\N	\N	Tobi	Aspin	\N	Male	Carlos Jaime R. Rosas	76	90702630-6676-4c22-ab09-143931f22ab2.png	Not Vaccinated	\N	\N	\N	\N	\N	\N	\N	\N	2026-03-10 05:46:33.94298	\N	\N	\N	Mabilo	New Washington	Aklan	\N	\N	\N	\N	\N
42	7a2d92a8-e04b-4019-bc5c-b3d0f913608b	f	\N	\N	\N	\N	\N	Chopper	Aspin	2023-12-01	Female	Mae R. Mose	82	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773213700/qr_codes/7a2d92a8-e04b-4019-bc5c-b3d0f913608b.png	Not Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773213699/dog_images/mu7c1mrmdrlu05zrst5e.jpg	\N	\N	\N	\N	\N	\N	\N	2026-03-11 07:21:40.975053	\N	\N	\N	Poblacion	New Washington	Aklan	\N	\N	\N	\N	\N
19	0ad910e2-3660-490e-9024-96a54320acdc	f	\N	\N	\N	\N	\N	LALA	Aspin	2025-03-01	Male	freschelle De Mateo De juan	69	0ad910e2-3660-490e-9024-96a54320acdc.png	Not Vaccinated	\N	\N	\N	\N	\N	\N	\N	\N	2026-03-06 08:21:22.078625	\N	\N	\N	Poblacion	New Washington	Aklan	\N	\N	\N	\N	\N
21	5bef9f0f-3e4b-41fc-8113-c423fa464af3	t	Other	\N	2026-03-20 17:18:16.617295	71	2026-03-20 17:18:16.617304	Luna	Perry'S Pequines	2023-08-28	Female	Skyzie mae allaga 	71	5bef9f0f-3e4b-41fc-8113-c423fa464af3.png	Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773305341/dog_images/gfgmjyp5xoojutjnl9lw.heic	2025-11-11	2026-11-11	2028-11-11	Mabilo	New Washington 	Aklan	In-house	2026-03-08 07:51:37.948128	\N	\N	\N	Mabilo	New Washington	Aklan	\N	\N	\N	\N	\N
24	f095bb26-7e89-46ad-9360-c2afb35110df	t	Other	\N	2026-03-20 17:19:44.804585	71	2026-03-20 17:19:44.804594	Broky	Spitz Pomeranian	2024-12-08	Male	Skyzie mae allaga 	71	f095bb26-7e89-46ad-9360-c2afb35110df.png	Vaccinated	1000080530.heic	2025-11-11	2026-11-11	2028-11-11	Mabilo	New washington	Aklan	In-house	2026-03-08 07:58:09.94935	\N	\N	\N	Mabilo	New Washington	Aklan	\N	\N	\N	\N	\N
62	078df097-600b-4ca9-930b-6ec7686d4534	f	\N	\N	\N	\N	\N	Luna	Perry'S Pequines	2023-08-28	Female	Skyzie mae allaga 	71	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774027077/qr_codes/078df097-600b-4ca9-930b-6ec7686d4534.png	Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774027075/dog_images/fcjucbmuctohduuad81c.jpg	2025-11-11	2026-11-11	2028-11-11	Mabilo	New Washington	Aklan	House	2026-03-20 17:17:57.788991	\N	\N	\N	Mabilo	New Washington	Aklan	\N	\N	f	\N	Anti-rabies
63	34bc33eb-9376-4afa-a822-cfc5e6d5b9ca	f	\N	\N	\N	\N	\N	Broky	Spitz Pomeranian	2024-12-08	Male	Skyzie mae allaga 	71	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774027171/qr_codes/34bc33eb-9376-4afa-a822-cfc5e6d5b9ca.png	Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774027170/dog_images/sjmp3jofcfrhnlrrxqev.jpg	2025-11-11	2026-11-11	2028-11-11	Mabilo	New Washington	Aklan	House	2026-03-20 17:19:31.41621	\N	\N	\N	Mabilo	New Washington	Aklan	\N	\N	f	\N	Anti-rabies
20	0d52763a-b1fc-403a-b371-4813966ed791	t	Other	\N	2026-03-23 14:59:16.733489	70	2026-03-23 14:59:16.733497	Snorpy	Pomeranian	2023-06-01	Male	Ma. Shey Leonor Trinidad 	70	0d52763a-b1fc-403a-b371-4813966ed791.png	Vaccinated	1000047478.jpg	2025-11-11	2026-11-11	2028-11-11	Mabilo	New Washington 	Aklan	In-house	2026-03-08 07:50:45.65444	\N	\N	\N	Mabilo	New Washington	Aklan	\N	\N	\N	\N	\N
68	62e85330-fb7d-4e1d-9a39-6582e93f7ad3	f	\N	\N	\N	\N	\N	Luka 	Mix Breed	2025-03-04	Male	Regilyn Delfin 	92	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774682640/qr_codes/62e85330-fb7d-4e1d-9a39-6582e93f7ad3.png	Not Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774682639/dog_images/n4exu2pgafe8rry4bx2o.jpg	\N	\N	\N	\N	\N	\N	\N	2026-03-28 07:24:00.63	\N	\N	\N	Laserna	Kalibo	Aklan 	\N	\N	f	\N	\N
43	36c79c1e-d7f6-498c-b492-7dcbd6321445	f	\N	\N	\N	\N	\N	Lala	Shih Tzu	2025-12-02	Female	Alma Española	84	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773215411/qr_codes/36c79c1e-d7f6-498c-b492-7dcbd6321445.png	Not Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773215410/dog_images/w9pf4stoygrsjyimvjtn.jpg	\N	\N	\N	\N	\N	\N	\N	2026-03-11 07:50:12.147709	\N	\N	\N	Poblacion 	New Washington 	Aklan 	\N	\N	\N	\N	\N
64	49b1e9e1-9dae-4834-b891-e86d128888f1	t	Other	\N	2026-03-23 14:49:24.867671	91	2026-03-23 14:49:24.867688	Broky	Spitz Pomeranian	2024-12-08	Female	Romel lemor	91	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774277349/qr_codes/49b1e9e1-9dae-4834-b891-e86d128888f1.png	Not Vaccinated	\N	\N	\N	\N	\N	\N	\N	\N	2026-03-23 14:49:09.728666	\N	\N	\N	Mabilo	New Washington	Aklan	\N	\N	f	\N	\N
55	42e2e6f6-699c-448d-bfee-8d63f176b0f4	f	\N	\N	\N	\N	\N	Mocha	Aspin	2025-10-01	Female	Rhea Concepcion	78	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773571036/qr_codes/42e2e6f6-699c-448d-bfee-8d63f176b0f4.png	Not Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773571035/dog_images/t7dmkt0pbg2mvynov9vv.jpg	\N	\N	\N	\N	\N	\N	\N	2026-03-15 10:37:16.601569	\N	\N	\N	Tambak	New Washington	Aklan	\N	\N	\N	\N	\N
48	ecd95961-a534-43e4-8df5-f6305743f4d7	f	\N	\N	\N	\N	\N	Bebeboi	Aspin	2024-01-01	Male	Ana mae Carillo	79	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773435805/qr_codes/ecd95961-a534-43e4-8df5-f6305743f4d7.png	Not Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773435804/dog_images/lp8bbo1tpekbbrvixf0m.jpg	\N	\N	\N	\N	\N	\N	\N	2026-03-13 21:03:25.973182	\N	\N	\N	Tambak 	New Washington 	Aklan 	\N	\N	\N	\N	\N
50	08c04956-18bc-4aca-bae9-46c9a3363e8e	f	\N	\N	\N	\N	\N	Baby girl	Aspin	2023-06-14	Female	Jean rasgo	81	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773569236/qr_codes/08c04956-18bc-4aca-bae9-46c9a3363e8e.png	Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773569251/dog_images/ly3epit1dcvhtw7guuey.jpg	2025-07-01	2026-07-01	2028-07-01	Tambak	New Washington	Aklan	House	2026-03-15 10:07:16.646544	\N	\N	\N	Tambak	New Washington	Aklan	\N	\N	\N	\N	Anti-rabies
45	ad691464-c051-4247-a27d-c002636115ec	f	\N	\N	\N	\N	\N	Parky	Labrador	2013-01-10	Male	Framilyn Fernandez	86	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773221374/qr_codes/ad691464-c051-4247-a27d-c002636115ec.png	Not Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773221373/dog_images/sxukiatkjvmymuay9gw0.jpg	\N	\N	\N	\N	\N	\N	\N	2026-03-11 09:29:35.006384	\N	\N	\N	Poblacion	New Washington	Aklan	\N	\N	\N	\N	\N
49	26b4b823-f804-41ee-8c88-c20b6664419c	f	\N	\N	\N	\N	\N	Coffee 	Mix Breed	2024-05-04	Male	Angel	73	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773436179/qr_codes/26b4b823-f804-41ee-8c88-c20b6664419c.png	Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773436179/dog_images/ypuv48bsgmudzzhri9of.jpg	2025-11-11	2026-11-11	2028-11-11	Mabilo	New Washington 	Aklan	House	2026-03-13 21:09:40.46968	\N	\N	\N	Mabilo 	New Washington 	Aklan 	\N	\N	\N	\N	Anti-rabies
65	2ea4c396-7ba7-42d5-8252-84c8f2ba5cc8	f	\N	\N	\N	\N	\N	Snorpy	Pomeranian	2023-06-01	Male	Ma. Shey Leonor Trinidad 	70	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774277945/qr_codes/2ea4c396-7ba7-42d5-8252-84c8f2ba5cc8.png	Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774277944/dog_images/ma3fwopiszvnjsqmfdgl.jpg	2025-11-11	2026-11-11	2028-11-11	Mabilo	New Washington	Aklan	House	2026-03-23 14:59:06.628427	\N	\N	\N	Mabilo	New Washington	Aklan	\N	\N	f	\N	Anti-rabies
52	9f794ffb-ebc4-4b22-b57d-0ba021c2efea	f	\N	\N	\N	\N	\N	Panda	Aspin	2025-06-01	Female	Armenda Dayo	77	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773570212/qr_codes/9f794ffb-ebc4-4b22-b57d-0ba021c2efea.png	Not Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773570211/dog_images/pewecyfjkkyp9ofcci11.jpg	\N	\N	\N	\N	\N	\N	\N	2026-03-15 10:23:32.920313	\N	\N	\N	Tambak	New Washington	Aklan	\N	\N	\N	\N	\N
53	eda5235f-65dc-49f0-99d5-92c07fbcd73e	f	\N	\N	\N	\N	\N	Jcob	Aspin	2025-05-01	Male	Armenda Dayo	77	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773570332/qr_codes/eda5235f-65dc-49f0-99d5-92c07fbcd73e.png	Not Vaccinated	\N	\N	\N	\N	\N	\N	\N	\N	2026-03-15 10:25:33.278111	\N	\N	\N	Tambak	New Washington	Aklan	\N	\N	\N	\N	\N
46	be5a22c5-be5b-4c54-a6a5-d47907b3a262	f	\N	\N	\N	\N	\N	Dowee	Shih Tzu	2025-09-12	Female	Pearleen Andrade	87	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773223851/qr_codes/be5a22c5-be5b-4c54-a6a5-d47907b3a262.png	Not Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773223851/dog_images/rmc1gz8ccehygjeyd9ms.jpg	\N	\N	\N	\N	\N	\N	\N	2026-03-11 10:10:53.050935	\N	\N	\N	Poblacion	New Washington	Aklan	\N	\N	\N	\N	\N
54	a8150ae6-e1d5-4c9b-9e21-c419957d42e5	f	\N	\N	\N	\N	\N	Thunder	Mix Breed	2025-10-30	Male	Jaren	80	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773570588/qr_codes/a8150ae6-e1d5-4c9b-9e21-c419957d42e5.png	Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773570638/dog_images/dthy97oogcf0ozyoz6zc.jpg	2025-08-30	2026-08-30	2028-08-30	Poblacion	New Washington	Aklan	Veterinary Clinic	2026-03-15 10:29:48.53781	\N	\N	\N	Tambak	New Washington	Aklan	\N	\N	\N	\N	Anti-rabies
44	426c63f0-ba85-4a38-832d-59a067cfebc1	f	\N	\N	\N	\N	\N	Twinkle 	Shih Tzu	2020-03-27	Female	Nena Lorenzo	85	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773219000/qr_codes/426c63f0-ba85-4a38-832d-59a067cfebc1.png	Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773218999/dog_images/hixvuqgetuzjr41xiper.jpg	2025-07-19	2026-02-19	2028-07-19	AClVDO	Kalibo	Aklan	Animal 	2026-03-11 08:50:01.081432	\N	\N	\N	Poblacion	New Washington	Aklan	\N	\N	\N	\N	Anti-rabies
69	91d7292d-a76b-4e5c-a775-f988d843a2a9	f	\N	\N	\N	\N	\N	bela	Askal	2024-03-29	Female	Andrea Francisco	93	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774752647/qr_codes/91d7292d-a76b-4e5c-a775-f988d843a2a9.png	Vaccinated	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774752646/dog_images/o3i65msn4idapp6ld36o.jpg	2026-02-12	2026-03-29	2029-02-12	In house 	Kalibo	Aklan	In house 	2026-03-29 02:50:47.684909	\N	\N	\N	Laserna	Kalibo 	Aklan 	\N	\N	f	\N	Anti Rabies 
\.


--
-- Data for Name: notifications; Type: TABLE DATA; Schema: public; Owner: final4_q7lh_user
--

COPY public.notifications (id, user_id, dog_id, title, message, type, milestone, due_date, is_read, dismissed, email_sent, created_at) FROM stdin;
25	93	69	Vaccination Overdue	Dear Andrea Francisco,<br><br>Our records indicate that <strong>bela</strong>'s vaccination is overdue. Please schedule a visit with your veterinarian as soon as possible to ensure bela's continued health and wellbeing.<br><br>Thank you for your attention.	overdue	overdue	2026-03-29	f	t	t	2026-03-29 02:50:47.70038
24	4	\N	New User Registration	New Owner registered: <strong>Andrea Francisco</strong><br>Email: andreafrancisci17@gmail.com	new_user	\N	\N	f	t	f	2026-03-29 02:40:35.228496
23	4	\N	New User Registration	New Owner registered: <strong>Regilyn Delfin </strong><br>Email: regilyndelfin686@gmail.com	new_user	\N	\N	f	t	f	2026-03-28 07:13:58.565323
27	4	\N	New User Registration	New Owner registered: <strong>Divine </strong><br>Email: reyesdivine683@gmail.com	new_user	\N	\N	f	t	f	2026-03-31 05:35:25.398083
28	4	\N	New User Registration	New Owner registered: <strong>Jerson Aranas, Perez</strong><br>Email: jp367093@gmail.com	new_user	\N	\N	f	t	f	2026-03-31 08:32:07.829767
21	4	\N	New User Registration	New Owner registered: <strong>Seo Haebom</strong><br>Email: haebomseo865@gmail.com	new_user	\N	\N	f	t	f	2026-03-19 06:21:21.115714
22	4	\N	New User Registration	New Owner registered: <strong>Romel lemor</strong><br>Email: romeldiazlachica@gmail.com	new_user	\N	\N	f	t	f	2026-03-19 09:10:00.87748
26	4	\N	New User Registration	New Owner registered: <strong>Louie James F Francisco</strong><br>Email: franciscoraulzonio01@gmail.com	new_user	\N	\N	f	t	f	2026-03-29 03:35:23.030228
\.


--
-- Data for Name: user; Type: TABLE DATA; Schema: public; Owner: final4_q7lh_user
--

COPY public."user" (id, username, email, email_verified, verification_token, last_notification_run, name, contact, barangay, municipality, province, address, profile_photo, password_hash, role, created_at, is_archived, archived_at) FROM stdin;
74	habibi	raffiepopes03@gmail.com	t	InJhZmZpZXBvcGVzMDNAZ21haWwuY29tIg.aa08vQ.Q2KX-kEAUkYcDsFkyZbXAsp7TQA	2026-03-20	Raffie P. David	09283411133	Mabilo	New Washington	Aklan	Mabilo, New Washington, Aklan	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773936691/profile_images/ftdqbvudlgipvjzhzxxw.jpg	scrypt:32768:8:1$sGC7WFei28CXIgjf$3a979fafe3641f9285bc123e7a3351e5e7dced5068f2a5377cdeab261f6953d0e026c64f6abf020cc15d689289a34320a485a6e986d715fc2a82e39f2cdcf9f5	owner	2026-03-08 09:09:16.955106	f	\N
93	drea	andreafrancisci17@gmail.com	t	\N	2026-03-29	Andrea Francisco	09707452779	Laserna	Kalibo 	Aklan 	C, lacerna street, Kalibo , Aklan 	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774752143/profile_images/t5sljlauyiruuim8qvfd.webp	scrypt:32768:8:1$9KgbeuW35E8zkUxu$f3001a336d553f938115f8facd3aaf65d9bb68957ba6addd006ed6891f80f56fbdda81cc63f1c2bfd1e6ecff27d238257767f5db11e49186b0d3ecaddf86605f	owner	2026-03-29 02:40:35.215641	f	\N
90	haebom	haebomseo865@gmail.com	t	\N	2026-03-19	Seo Haebom	09972501034	Sta. Cruz Bigaa 	Lezo	Aklan	Sta. Cruz Bigaa , Lezo, Aklan	\N	scrypt:32768:8:1$4UvRuaCyrqaW4C5Y$a6aae81043cb12bd78b4cbe81010c3bbfff1d8f6b251a20293e9676420d0c4057efc4b5a40cedbdfb28d90660a86519ed1065e9f3758a0304e57f634b92485d0	owner	2026-03-19 06:21:21.101903	f	\N
73	angel	reyangel641@gmail.com	t	InJleWFuZ2VsNjQxQGdtYWlsLmNvbSI.aa00EA.aG7jJmdbOcEYbxynnE-TrG4tfA4	2026-03-26	Angel	09671751184	Mabilo 	New Washington 	Aklan 	Mabilo , New Washington , Aklan 	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774461828/profile_images/o5rc0idbzvpuwjkjxrfh.jpg	scrypt:32768:8:1$wCnCZzAQve8bqbsu$e76653efc533930a98dd7e9b848ac17fa485fe891951aa2a87fd63e8c4405dcb09c8886855ce666879ce1c33e0aa1005ff40cc59900e37910191f7acf62e485e	owner	2026-03-08 08:32:16.15536	f	\N
75	kayl	tkyle7730@gmail.com	t	InRreWxlNzczMEBnbWFpbC5jb20i.aa1CRw.XjiP4ZMS2QQdbkVPuTL5fmxMAwc	2026-03-20	Kyle Trinidad	09154306513	Mabilo	New Washington	Aklan	Mabilo, New Washington, Aklan	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773571159/profile_images/kcvykk1uymovlkxhez9p.jpg	scrypt:32768:8:1$sgvHBp0fDMVL9oya$cb7078923c131ddbf1a6b5451d4e95e11c3a6adb7afaf91a156481d518a165a541cec8a2de921c124368576d3dcaeebe8e5cc0117acbfebc41449069ddcae0be	owner	2026-03-08 09:32:55.246208	f	\N
69		dejuanbrian013@gmail.com	t	ImRlanVhbmJyaWFuMDEzQGdtYWlsLmNvbSI.aaqNNg.Z2kSVV2wJTrqU22ybsPFU1uBrPI	2026-03-06	freschelle De Mateo De juan	09099398035	Poblacion	New Washington	Aklan	Poblacion, New Washington, Aklan	\N	scrypt:32768:8:1$5tJoYDGqauSPYRKj$df2f32edfdff055e9b517ad56d94288efafedf9c00d16e736fa065655339fbb687f3f08d6b88f34dcc698fbbef1ebfd68e4e952bbd84d0b0accfc99ba0284178	owner	2026-03-06 08:15:50.17905	f	\N
94	louie	franciscoraulzonio01@gmail.com	t	\N	\N	Louie James F Francisco	09388251408	Claserna st. Purok4	Kalibo	Aklan	Claserna st. Purok4, Kalibo, Aklan	\N	scrypt:32768:8:1$QZiOhYq4iPHE0fwe$df3c497c309837e0e16c10494fb8c5092c3cba9e6d99ee89d32929b21710b388dac9b85f8e538b4724b36e6e49d0d3c68d975f87b4ed160b84878bf743cc1d21	owner	2026-03-29 03:35:23.018124	f	\N
4	admin	admin@gmail.com	t	\N	2026-04-02	Administrator	\N	\N	\N	\N	\N	\N	scrypt:32768:8:1$yEZCN5sp0jCbHAlK$325fb1cfc5386884fa72235c41e524eaf89be9cc83309210411ec93ca82ebf0bbf2ce04d6945a28e773d735d0e8b06f6f76f28304e779eccf9acf8af80c52506	admin	2026-02-21 18:17:43.466539	f	\N
70	shey	trinidadshey4@gmail.com	t	InRyaW5pZGFkc2hleTRAZ21haWwuY29tIg.aa0g-Q.OC2at_kRjVHUH7DbuGOIUl1NcAg	2026-03-23	Ma. Shey Leonor Trinidad 	09158086987	Mabilo	New Washington	Aklan	Mabilo, New Washington, Aklan	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774277798/profile_images/r9cgts6sgglvbwlmvk4k.jpg	scrypt:32768:8:1$QNwxXcuSKZWkYyPn$e552f5d482d0b35519d16af5152fa79b419f404c44c8916d1688df8dc6a7fae4f6b5b402136c34115806814eb6ca2b462f38fb9b8fc183a5bfabdfefe57a5e37	owner	2026-03-08 07:10:49.659772	f	\N
66	ynez_0321	zenycarpio24@gmail.com	t	\N	2026-03-03	Zeny Carpio	09566391848	Mabilo	New Washington	Aklan	Mabilo, New Washington, Aklan	IMG20260301003550.jpg	scrypt:32768:8:1$rCk5Xg4lT08ImqYQ$ac40be29a48dfeca7c419d438885a4043b0602f2b6ac0c484808b266adc9a2100df3d623855c5ea192d9ea3e1ba8b5c6ca3e4926c3cde75ba8a87096a391d34a	owner	2026-03-02 16:02:55.249634	f	\N
77	armendaq0	arminarminda5@gmail.com	t	\N	2026-03-15	Armenda Dayo	09487046160	Tambak	New Washington	Aklan	Tambak, New Washington, Aklan	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773569505/profile_images/uni3umccvrcr6nb31wop.jpg	scrypt:32768:8:1$Xgoelp7s4adVlF7f$b1aed45564e806ec85474ce53f1f954f4dfb72a60ad953235b876c5cbc7492da32d62259542ffff15aae9bf477c491f73aec27efaa4ed344e3e401c09ade1420	owner	2026-03-10 06:58:40.431483	f	\N
76	deathchukee	cjjemaime@gmail.com	t	\N	2026-03-10	Carlos Jaime R. Rosas	09394749621	Mabilo	New Washington	Aklan	Mabilo, New Washington, Aklan	\N	scrypt:32768:8:1$Om10OtMChTDZoYm2$12ecfdc967e0dcf0e83ccfcee12323ec28cd85e0fcb3b0b579b67a90de1377c7bb35195326f6e02a7c5ec6c87d4e1f2f011e1a82b692c1dab4b795b6dbb203d3	owner	2026-03-10 05:45:17.348746	f	\N
91	lermz10	romeldiazlachica@gmail.com	t	\N	2026-03-26	Romel lemor	09100586637	Mabilo	New Washington	Aklan	Mabilo, New Washington, Aklan	\N	scrypt:32768:8:1$ww9NmNBSnJPJCFQY$e061770e146a3f195a5f9739ef9529f3322da8acdfc65e1d38c5298c7b93e7c0592590be7705926fc4486ebc9082e9c45f3ae974ffcd198f13d20e7b83f4bfbe	owner	2026-03-19 09:10:00.782288	f	\N
95	divinecipriano	reyesdivine683@gmail.com	t	\N	2026-03-31	Divine 	09634625144	Buswang Old 	Kalibo	Aklan	Buswang Old , Kalibo, Aklan	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774935919/profile_images/a44w8auvomdffxl4zg9s.jpg	scrypt:32768:8:1$aBgOevsdaG7dKv4j$1561e9123027cd3bf477802106af95a2645cdf59251f37a86e8ce1e1e410189f269d43889a525aa27d5374d20375424487bf2ce5253a13506116dcc1af203729	owner	2026-03-31 05:35:25.375518	f	\N
82	mae	twistedsunshine09@gmail.com	t	\N	2026-03-11	Mae R. Mose	09388236930	Poblacion	New Washington	Aklan	Poblacion, New Washington, Aklan	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773213556/profile_images/gktjci9yvjg3wboycnol.jpg	scrypt:32768:8:1$YMRmE521dy6PB6IU$8f8449f93a6b34b87d1c231f33d46b615037a69ebac645e15825ba55a81a94b23f499f5bf406c94521203bd60bf919cba03edb2a3d12bba06acf461d03a25c5a	owner	2026-03-11 07:17:54.475915	f	\N
84	alma	gobrisalma21@gmail.com	t	\N	2026-03-14	Alma Española	09638625436	Poblacion 	New Washington 	Aklan 	Poblacion , New Washington , Aklan 	\N	scrypt:32768:8:1$zEHaRauuXwmv0nnw$e7430eb974e4bd247296cf2ad63a970182f7438cfe79322c8d249bf21eb41d89f276ad7a89e60ee3c99140b14a81d7bd0572a5e74cd28f35372579d7c539ade7	owner	2026-03-11 07:45:06.782035	f	\N
87	nashkobie	andradenovelkent09@gmail.com	t	\N	2026-03-14	Pearleen Andrade	09266549509	Poblacion	New Washington	Aklan	Poblacion, New Washington, Aklan	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773223738/profile_images/vg8vnfmlc4rynx1rngs2.jpg	scrypt:32768:8:1$oW5h6PKIG4zIQxOf$f0b597dfddd6d59d042dfb63ac970882ca73566e6407835fce600dcc0637fab2eebb3c6cb736c08cdf09fc4d255b7f44f092878196aace649ec61cbbd40a7e80	owner	2026-03-11 10:05:32.97901	f	\N
79	namie	anamaecarillo005@gmail.com	t	\N	2026-03-14	Ana mae Carillo	09774292076	Tambak 	New Washington 	Aklan 	Tambak , New Washington , Aklan 	1000005636.jpg	scrypt:32768:8:1$RXrjcXQPHhLBrXmj$45172a1c62c3156ede5fddfa95191d2fe73494a91e619e9a82d3e8d821a1a8b722ea87de70f5d1b31b2bba1b49af32dad7b01cf2570da1b8d4b7fa7a98f62cd1	owner	2026-03-10 07:50:58.394569	f	\N
80	jareng	jarenmanagaytay@gmail.com	t	\N	2026-03-15	Jaren	09482515670	Tambak	New Washington	Aklan	Tambak, New Washington, Aklan	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773570430/profile_images/wqacrbqfs33tfortvstn.jpg	scrypt:32768:8:1$0che6OKwBLOq3I2U$f42c86056690e97a16d1cd59e2dae9f2970dde331fea22946f867f2dededaa2029227c75d61aadd0b5f93a53458d7e57fef10574929ecd41608b84d96238adbf	owner	2026-03-10 08:23:43.80487	f	\N
81	jeanrasgo	joeffrier@gmail.com	t	\N	2026-03-22	Jean rasgo	09958573709	Tambak	New Washington	Aklan	Tambak, New Washington, Aklan	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773568905/profile_images/og3uthzkxtig7b9tmxkt.jpg	scrypt:32768:8:1$e5yP03i3OSWAiAzA$759ec55a951ad14bf0977acc6b4421f00c27e499bfe97ecfb175cd57a417ec71aa1e7897b1d91e9533db5184a03bb885958f8eea09751134c334727118eecf27	owner	2026-03-10 08:59:01.951008	f	\N
71	sky	skyziemaeallaga097@gmail.com	t	InNreXppZW1hZWFsbGFnYTA5N0BnbWFpbC5jb20i.aa0h-w.UOzklNC28UKjNoz3XVKQBcoZVbY	2026-03-21	Skyzie mae allaga 	09771042781	Mabilo	New Washington	Aklan	Mabilo, New Washington, Aklan	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774022941/profile_images/cebvagitzwrjbimwa2mo.jpg	scrypt:32768:8:1$QL1XMDH8xhplvGDa$4b1a90f53ba562486e45faddff92d88e95912705a35ef9e3c851f27972f4c1239dc3309329d418042026b19478b854da8e47331fd8170bf7d32fe5ffde1a899c	owner	2026-03-08 07:14:59.858959	f	\N
78	rhea	rheaconcepcion60@gmail.com	t	\N	2026-03-18	Rhea Concepcion	09098891365	Tambak	New Washington	Aklan	Tambak, New Washington, Aklan	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773570906/profile_images/omgcsyhj0yh2ga7vfmpl.jpg	scrypt:32768:8:1$mlagwMZUatz4YFTH$3991cfa1a53e49686265849a259dbf34b51ed4feb5f196d243526fae276c3396a6550e2bd7771681954c48cdc0fcea4414ac9fbaf147772c746e3324e8e20d61	owner	2026-03-10 07:26:37.101488	f	\N
85	nena	floresangelmay6@gmail.com	t	\N	2026-03-11	Nena Lorenzo	09388334852	Poblacion	New Washington	Aklan	Poblacion, New Washington, Aklan	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773218595/profile_images/v9aazwhbdfot0nfybj5l.jpg	scrypt:32768:8:1$FQn03EHELXNAbAeX$fff0880342525af86ca7c9f9b60796aed4849948db76e041c5b6ef92d7127fa266dbd29c9bef1146feda2f65776ba847901edb0d4c6e49fc76c3bda0f4465d58	owner	2026-03-11 08:38:16.48772	f	\N
86	fram	framframfernandez@gmail.com	t	\N	2026-03-11	Framilyn Fernandez	09108774813	Poblacion	New Washington	Aklan	Poblacion, New Washington, Aklan	https://res.cloudinary.com/di6rvl2bn/image/upload/v1773221144/profile_images/dsusdpbvjhit0yyyywv8.jpg	scrypt:32768:8:1$M6dpT1GjI1W2Puhh$90fec4e95768641a9f2dc294450018e76b1b97e84de8ff773de3736eba347dbba3e1a352304bf83993f999c76e323c5a2725ae59aa99cd6cad17056b8a7ba0a6	owner	2026-03-11 09:23:55.976357	f	\N
96	jerson	jp367093@gmail.com	t	\N	2026-04-01	Jerson Aranas, Perez	09390844375	Poblacion 	Kalibo	Aklan	Poblacion , Kalibo, Aklan	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774946198/profile_images/mk4dtejxquad7ii97rzb.jpg	scrypt:32768:8:1$ryhtbzMCAjk9HR5u$3797cc786f0c2629657ddb0c99fc22845fac50ce08dbacfee8c1e447c4a63d1958b9aae99bf720a371f8f96de67495eab121d4185168231f6477716c8daa2584	owner	2026-03-31 08:32:07.721543	f	\N
88	rold24	geroldconsigna21@gmail.com	t	\N	2026-03-29	Gerold Consigna	09673093736	NA	NA	NA	NA, NA, NA	\N	scrypt:32768:8:1$3GZusHVTdYGnC1G1$fb9a413d54ac021a54c2f99b90bf048a242faaf40ead25ec8a703c94927a082b07af50eaa9e2255690163a262306ffc85b7c5193a153371566a4af820808de23	owner	2026-03-13 14:31:11.58291	f	\N
92	reg	regilyndelfin686@gmail.com	t	\N	2026-03-28	Regilyn Delfin 	09638053305	Laserna	Kalibo	Aklan 	Laserna , Kalibo, Aklan 	https://res.cloudinary.com/di6rvl2bn/image/upload/v1774682345/profile_images/eljlrqspogtv7novkpve.jpg	scrypt:32768:8:1$wmx8m6MJvNEKFwIR$9d0bc0845a6a65fd527180f847b46dfacd658e42157c694385ddd097daa6a66628e4a2a7c6ab52d5f49e204f183e0b11b2b5abe8f58dc1228f7cfa27f9f6de08	owner	2026-03-28 07:13:58.475125	f	\N
\.


--
-- Name: dog_id_seq; Type: SEQUENCE SET; Schema: public; Owner: final4_q7lh_user
--

SELECT pg_catalog.setval('public.dog_id_seq', 70, true);


--
-- Name: notifications_id_seq; Type: SEQUENCE SET; Schema: public; Owner: final4_q7lh_user
--

SELECT pg_catalog.setval('public.notifications_id_seq', 28, true);


--
-- Name: user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: final4_q7lh_user
--

SELECT pg_catalog.setval('public.user_id_seq', 96, true);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: final4_q7lh_user
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: dog dog_pkey; Type: CONSTRAINT; Schema: public; Owner: final4_q7lh_user
--

ALTER TABLE ONLY public.dog
    ADD CONSTRAINT dog_pkey PRIMARY KEY (id);


--
-- Name: dog dog_uuid_key; Type: CONSTRAINT; Schema: public; Owner: final4_q7lh_user
--

ALTER TABLE ONLY public.dog
    ADD CONSTRAINT dog_uuid_key UNIQUE (uuid);


--
-- Name: notifications notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: final4_q7lh_user
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);


--
-- Name: notifications unique_notification_per_dog_per_milestone; Type: CONSTRAINT; Schema: public; Owner: final4_q7lh_user
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT unique_notification_per_dog_per_milestone UNIQUE (user_id, dog_id, type, milestone);


--
-- Name: user user_email_key; Type: CONSTRAINT; Schema: public; Owner: final4_q7lh_user
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT user_email_key UNIQUE (email);


--
-- Name: user user_pkey; Type: CONSTRAINT; Schema: public; Owner: final4_q7lh_user
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT user_pkey PRIMARY KEY (id);


--
-- Name: user user_username_key; Type: CONSTRAINT; Schema: public; Owner: final4_q7lh_user
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT user_username_key UNIQUE (username);


--
-- Name: dog dog_deleted_by_owner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: final4_q7lh_user
--

ALTER TABLE ONLY public.dog
    ADD CONSTRAINT dog_deleted_by_owner_id_fkey FOREIGN KEY (deleted_by_owner_id) REFERENCES public."user"(id);


--
-- Name: dog dog_owner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: final4_q7lh_user
--

ALTER TABLE ONLY public.dog
    ADD CONSTRAINT dog_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public."user"(id);


--
-- Name: notifications notifications_dog_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: final4_q7lh_user
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_dog_id_fkey FOREIGN KEY (dog_id) REFERENCES public.dog(id) ON DELETE CASCADE;


--
-- Name: notifications notifications_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: final4_q7lh_user
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: DEFAULT PRIVILEGES FOR SEQUENCES; Type: DEFAULT ACL; Schema: -; Owner: postgres
--

ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT ALL ON SEQUENCES TO final4_q7lh_user;


--
-- Name: DEFAULT PRIVILEGES FOR TYPES; Type: DEFAULT ACL; Schema: -; Owner: postgres
--

ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT ALL ON TYPES TO final4_q7lh_user;


--
-- Name: DEFAULT PRIVILEGES FOR FUNCTIONS; Type: DEFAULT ACL; Schema: -; Owner: postgres
--

ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT ALL ON FUNCTIONS TO final4_q7lh_user;


--
-- Name: DEFAULT PRIVILEGES FOR TABLES; Type: DEFAULT ACL; Schema: -; Owner: postgres
--

ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT ALL ON TABLES TO final4_q7lh_user;


--
-- PostgreSQL database dump complete
--

\unrestrict vYj2FvwDyKPn0lLNgKk5E188NhSD1bvFuEfwAg8as16R2aQBhx44LNofVwX8Wsp

