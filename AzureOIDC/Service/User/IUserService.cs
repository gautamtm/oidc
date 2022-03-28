using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AzureOIDC.Service.Entity;

namespace AzureOIDC.Service
{
    public interface IUserService
    {
        Task<User> GetUserByEmail(string emailAddress);
    }
}
