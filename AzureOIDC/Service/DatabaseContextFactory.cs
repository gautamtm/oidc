using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AzureOIDC.Service
{
    public class DatabaseContextFactory : IDatabaseContextFactory
    {
        private readonly string _connectionString;
        public DatabaseContextFactory(string connectionString)
        {
            _connectionString = connectionString;
        }

        public IDatabaseContext Create()
        {
            return new OIDCDbContext(_connectionString);
        }


    }
    
}
