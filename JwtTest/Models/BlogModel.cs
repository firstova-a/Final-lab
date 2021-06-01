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
    public class BlogModel
    {
        public int? Id { get; set; }

        [Required(ErrorMessage = "Название птицы является обязательным")]
        [DisplayName("Название птицы")]
        public string Bird { get; set; }
        
        [DisplayName("Название птицы на латинском")]
        public string BirdInLatin { get; set; }
        
        [DisplayName("Количество")]
        public int Count { get; set; }
        
        [DisplayName("Дата и время")]
        [DisplayFormat(DataFormatString = "{0:dd MMM yyyy}")]
        public DateTime Time { get; set; }
        
        [DisplayName("Погода")]
        public string Weather { get; set; }
        
        [Required(ErrorMessage = "Место является обязательным")]
        [DisplayName("Место")]
        public string Place { get; set; }
        
        [DisplayName("Комментарий")]
        public string Comment { get; set; }
        
        [DisplayName("Фото")]
        public IFormFile Picture { get; set; }
    }
}
