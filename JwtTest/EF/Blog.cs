﻿using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JwtTest.EF
{
    public class Blog
    {
        public int Id { get; set; }
        public string Bird { get; set; }
        public string BirdInLatin { get; set; }
        public int Count { get; set; }
        public string Weather { get; set; }
        public string Place { get; set; }
        public string Comment { get; set; }
        public DateTime Time { get; set; }
        
        public string Picture { get; set; }
        public virtual Person Author { get; set; }
    }
}
