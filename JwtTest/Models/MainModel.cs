using JwtTest.EF;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace JwtTest.Models
{
    public class MainModel
    {
        public string ErrorMessage { get; set; }
        public List<Blog> Blogs { get; set; }
        public Person User { get; set; }
    }
}
