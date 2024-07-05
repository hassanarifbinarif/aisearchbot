from django.db.models import Lookup, CharField

class IContainsAny(Lookup):
    lookup_name = 'icontains_any'

    def as_sql(self, compiler, connection):
        lhs, lhs_params = self.process_lhs(compiler, connection)
        rhs, rhs_params = self.process_rhs(compiler, connection)
        terms = rhs_params[0].split()
        sql = ' OR '.join([f'{lhs} ILIKE %s' for term in terms])
        params = [f'%{term}%' for term in terms]
        return sql, params

# Register the custom lookup with CharField
CharField.register_lookup(IContainsAny)