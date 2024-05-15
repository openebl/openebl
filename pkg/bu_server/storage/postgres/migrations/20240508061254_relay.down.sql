ALTER TABLE public.business_unit_authentication ADD CONSTRAINT business_unit_authentication_business_unit_id_fkey FOREIGN KEY (business_unit_id) REFERENCES public.business_unit(id) ON DELETE CASCADE;
ALTER TABLE public.business_unit ADD CONSTRAINT business_unit_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.application(id) ON DELETE CASCADE;
DROP TABLE relay_event;
