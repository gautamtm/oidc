using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AzureOIDC.Service.Entity
{
    public class User
    {
        public string EmailAddress { get; set; }
        public Guid UserGuid { get; set; }
        public string DisplayName { get; set; }

    }
}
