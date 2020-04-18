﻿namespace Application.Categories.Queries.List
{
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;
    using AutoMapper;
    using AutoMapper.QueryableExtensions;
    using Common.Exceptions;
    using Common.Interfaces;
    using Common.Models;
    using Domain.Entities;
    using MediatR;
    using Microsoft.EntityFrameworkCore;

    public class ListCategoriesQueryHandler : IRequestHandler<ListCategoriesQuery, MultiResponse<ListCategoriesResponseModel>>
    {
        private readonly IAuctionSystemDbContext context;
        private readonly IMapper mapper;

        public ListCategoriesQueryHandler(IAuctionSystemDbContext context, IMapper mapper)
        {
            this.context = context;
            this.mapper = mapper;
        }

        public async Task<MultiResponse<ListCategoriesResponseModel>> Handle(ListCategoriesQuery request, CancellationToken cancellationToken)
        {
            var categories = await this.context
                .Categories
                .Include(c => c.SubCategories)
                .ProjectTo<ListCategoriesResponseModel>(this.mapper.ConfigurationProvider)
                .ToListAsync(cancellationToken);

            if (!categories.Any())
            {
                throw new NotFoundException(nameof(Category));
            }

            return new MultiResponse<ListCategoriesResponseModel>(categories);
        }
    }
}