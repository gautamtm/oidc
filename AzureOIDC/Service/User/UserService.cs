using AzureOIDC.Service.Entity;
using Dapper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AzureOIDC.Service
{
    public class UserService : IUserService
    {
        public IDatabaseContext _context;
        public UserService(IDatabaseContext context) {
            _context = context;
        }

        public async Task<User> GetUserByEmail(string emailAddress)
        {
            var sql = @"SELECT *
                        FROM [Users]
                        WHERE WorkEmail = @emailAddress";
            var user = await _context.Connection.QueryFirstOrDefaultAsync<User>(sql, new { emailAddress = emailAddress });
            return user;
        }
    }
}
