// routes/profit.js
module.exports = function makeProfitRoutes({ db, isAuthenticated, restrictRoute }) {
  const express = require('express');
  const router  = express.Router();

  /* helper identical to the one in app.js */
  const pad = n => String(n).padStart(2, '0');

  /* ─────────── GET /profit ─────────── */
  router.get(
    '/profit',
    isAuthenticated,
    restrictRoute('/profit'),
    async (req, res) => {
      try {
        const accountId     = req.session.user.accountId;

        /* 0️⃣  Base queries */
        let salesQuery   = db.collection('sales').where('accountId','==',accountId);
        let expenseQuery = db.collection('expenses').where('accountId','==',accountId);
        let recQuery     = db.collection('recurringMonthly').where('accountId','==',accountId);

        const { month, year } = req.query;

        /* 1️⃣  Date filters (unchanged logic) */
        if (month) {
          const [y,m]   = month.split('-');
          const start   = `${month}-01`;
          let nextM     = parseInt(m,10)+1,
              nextY     = parseInt(y,10);
          if (nextM>12){ nextM=1; nextY++; }
          const next    = `${nextY}-${pad(nextM)}-01`;
          salesQuery   = salesQuery.where('saleDate','>=',start).where('saleDate','<',next);
          expenseQuery = expenseQuery.where('saleDate','>=',start).where('saleDate','<',next);

        } else if (year) {
          const start = `${year}-01-01`;
          const end   = `${parseInt(year)+1}-01-01`;
          salesQuery   = salesQuery.where('saleDate','>=',start).where('saleDate','<',end);
          expenseQuery = expenseQuery.where('saleDate','>=',start).where('saleDate','<',end);

        } else {
          const curY  = new Date().getFullYear();
          const start = `${curY}-01-01`;
          const end   = `${curY+1}-01-01`;
          salesQuery   = salesQuery.where('saleDate','>=',start).where('saleDate','<',end);
          expenseQuery = expenseQuery.where('saleDate','>=',start).where('saleDate','<',end);
        }

        /* 2️⃣  Fetch */
        const [salesSnap, expSnap, recSnap] = await Promise.all([
          salesQuery.get(),
          expenseQuery.get(),
          recQuery.get()
        ]);

        const todayYM = new Date().toISOString().substring(0,7);   // "YYYY-MM"

        const recRows = recSnap.docs
          .map(d => d.data())
          .filter(d => !d.deleted && d.month <= todayYM);

        /* helper */
        function paidPortion(row){
          const status = row.expenseStatus || '';
          const cost   = +row.expenseCost || 0;
          switch(status){
            case 'Not Paid'                  : return 0;
            case 'Half Cash + Not Paid'      :
            case 'Half Online + Not Paid'    :
              return row.expenseDetail1 !== undefined
                     ? (+row.expenseDetail1 || 0)
                     : cost/2;
            default                          : return cost;
          }
        }

        const sales    = salesSnap.docs.map(d => d.data());
        const expenses = expSnap.docs.map(d => d.data());

        /* 3️⃣  Totals */
        const totalProfit     = sales.reduce((s,x)=> s + x.profit,0);
        const totalExpenses   = [...expenses, ...recRows]
                                  .reduce((s,x)=> s + paidPortion(x),0);
        const totalGstPayable = sales.reduce((s,x)=> s + (x.gstPayable||0),0);
        const netProfit       = totalProfit - totalExpenses - totalGstPayable;

        /* 4️⃣  Month buckets */
        const profitByMonth = {};
        sales.forEach(s=>{
          const m = s.saleDate.substring(0,7);
          if(!profitByMonth[m]) profitByMonth[m]={ profit:0, expenses:0, gst:0, netProfit:0 };
          profitByMonth[m].profit += s.profit;
          profitByMonth[m].gst    += (s.gstPayable||0);
        });
        expenses.forEach(e=>{
          const m = e.saleDate.substring(0,7);
          if(!profitByMonth[m]) profitByMonth[m]={ profit:0, expenses:0, gst:0, netProfit:0 };
          profitByMonth[m].expenses += paidPortion(e);
        });
        recRows.forEach(r=>{
          const m = r.month;
          if(!profitByMonth[m]) profitByMonth[m]={ profit:0, expenses:0, gst:0, netProfit:0 };
          profitByMonth[m].expenses += paidPortion(r);
        });
        Object.entries(profitByMonth).forEach(([m,row])=>{
          row.netProfit = row.profit - row.expenses - row.gst;
          if(row.profit===0 && row.expenses===0 && row.gst===0) delete profitByMonth[m];
        });

        /* 5️⃣  Render */
        res.render('profit',{
          sales,
          expenses,
          totalProfit,
          totalExpenses,
          totalGstPayable,
          netProfit,
          profitByMonth,
          monthFilter: month || '',
          yearFilter : req.query.year || ''
        });

      } catch(err){
        res.status(500).send(err.toString());
      }
    }
  );

  return router;
};
