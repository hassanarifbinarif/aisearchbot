from django.db.models import Lookup, CharField
from django.contrib.postgres.fields import ArrayField


class IContainsAny(Lookup):
    lookup_name = 'icontains_any'

    def as_sql(self, compiler, connection):
        lhs, lhs_params = self.process_lhs(compiler, connection)
        rhs, rhs_params = self.process_rhs(compiler, connection)
        terms = rhs_params[0].split()
        sql = ' OR '.join([f'{lhs} ILIKE %s' for term in terms])
        params = [f'%{term}%' for term in terms]
        return sql, params
    

class ArrayIContains(Lookup):
    lookup_name = 'iarraycontains'
    
    def as_sql(self, compiler, connection):
        lhs, lhs_params = self.process_lhs(compiler, connection)
        rhs, rhs_params = self.process_rhs(compiler, connection)

        # Ensure rhs_params is correctly formatted as a PostgreSQL array literal
        if isinstance(rhs_params, list):
            # Convert each parameter to string (assuming they are strings)
            rhs = '{' + ','.join(str(param) for param in rhs_params) + '}'
            rhs_params = []

        sql = (
            "EXISTS (SELECT 1 FROM unnest(%s::text[]) AS elem WHERE LOWER(elem) = ANY(ARRAY(SELECT LOWER(unnest(%s)))))"
        )
        
        return sql, [lhs, rhs]


CharField.register_lookup(IContainsAny)
ArrayField.register_lookup(ArrayIContains)